#!/usr/bin/env python3
"""
AI Emotion API - Integrated with TEDDY Flask App
Detects emotions from PNG images and MP3 audio files.
"""

from __future__ import annotations
import json
import os
import tempfile
import re
from typing import Dict, List, Tuple, Any
import asyncio
from datetime import datetime

# Flask and dependencies
from flask import Blueprint, request, jsonify, current_app
import requests

# ML libraries (these will be installed separately)
try:
    import numpy as np
    from fer import FER
    import cv2
    from faster_whisper import WhisperModel
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: ML libraries not installed. Emotion API will use mock responses.")

# Create Blueprint
emotion_bp = Blueprint('emotion_api', __name__, url_prefix='/api/emotion')

# Global ML models (lazy initialization)
_fer_detector: 'FER | None' = None
_whisper_model: 'WhisperModel | None' = None

# Emotion keyword mapping
EMOTION_KEYWORDS: Dict[str, List[str]] = {
    "happiness": ["happy", "good", "great", "excited", "joy", "wonderful", "amazing", "love"],
    "sadness": ["sad", "miss", "unhappy", "lonely", "down", "depressed", "hurt", "cry"],
    "anger": ["mad", "angry", "frustrated", "hate", "annoyed", "upset"],
    "fear": ["scared", "nervous", "anxious", "afraid", "worried", "panic"],
    "surprise": ["guess what", "amazing", "wow", "exciting", "shocked", "unexpected"],
    "neutral": ["tired", "nothing", "don't feel", "meh", "okay", "fine"],
    "disgust": ["disgust", "gross", "yuck", "sick", "terrible"],
    "trust": ["trust", "appreciate", "confidence", "believe", "safe"],
    "anticipation": ["anticipate", "eager", "waiting", "excited", "hope", "looking forward"],
    "farewell": ["goodnight", "goodbye", "bye teddy", "see you later"],
}

# Priority order for emotion classification
EMOTION_PRIORITY = [
    "anger", "fear", "disgust", "sadness", "surprise", 
    "happiness", "anticipation", "trust", "neutral", "farewell"
]

# FER to API emotion mapping
FER_TO_API_MAP = {
    "angry": "anger",
    "disgust": "disgust", 
    "fear": "fear",
    "happy": "happiness",
    "sad": "sadness",
    "surprise": "surprise",
    "neutral": "neutral",
}

def verify_api_key():
    """Verify API key from request headers"""
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return False
    
    # Get config from Flask app
    config = current_app.config.get('TEDDY_CONFIG', {})
    return api_key == config.get('api_key', '')

def get_fer_detector():
    """Get or initialize FER detector"""
    if not ML_AVAILABLE:
        return None
    
    global _fer_detector
    if _fer_detector is None:
        config = current_app.config.get('TEDDY_CONFIG', {})
        _fer_detector = FER(mtcnn=bool(config.get("fer_mtcnn", False)))
    return _fer_detector

def get_whisper_model():
    """Get or initialize Whisper model"""
    if not ML_AVAILABLE:
        return None
    
    global _whisper_model
    if _whisper_model is None:
        config = current_app.config.get('TEDDY_CONFIG', {})
        device = config.get("whisper_device", "cpu")
        if device not in ("cpu", "auto"):
            device = "cpu"
        model_size = config.get("whisper_model", "base")
        _whisper_model = WhisperModel(model_size, device=device, compute_type="int8")
    return _whisper_model

def analyze_image_content(content: bytes) -> Dict[str, Any]:
    """Analyze emotion in image content"""
    if not ML_AVAILABLE:
        # Mock response when ML libraries aren't available
        return {
            "emotion": "happiness",
            "scores": {"happiness": 0.8, "neutral": 0.2},
            "faces": 1,
            "mock": True
        }
    
    # Decode PNG bytes to BGR image
    data = np.frombuffer(content, dtype=np.uint8)
    img = cv2.imdecode(data, cv2.IMREAD_COLOR)
    if img is None:
        return {"emotion": "none", "scores": {}, "faces": 0}

    detector = get_fer_detector()
    if detector is None:
        return {"emotion": "none", "scores": {}, "faces": 0}
    
    detections = detector.detect_emotions(img)

    if not detections:
        return {"emotion": "none", "scores": {}, "faces": 0}

    # Aggregate emotions across all faces
    agg: Dict[str, float] = {}
    for det in detections:
        emotions = det.get("emotions", {})
        for k, v in emotions.items():
            agg[k] = agg.get(k, 0.0) + float(v)
    
    # Average across faces
    for k in list(agg.keys()):
        agg[k] /= len(detections)

    # Map FER labels to API labels
    mapped = {FER_TO_API_MAP.get(k, k): float(v) for k, v in agg.items()}

    # Find top emotion
    if mapped:
        top_emotion = max(mapped.items(), key=lambda kv: kv[1])[0]
    else:
        top_emotion = "none"

    return {"emotion": top_emotion, "scores": mapped, "faces": len(detections)}

def transcribe_mp3_content(content: bytes) -> Tuple[str, float]:
    """Transcribe MP3 audio content"""
    if not ML_AVAILABLE:
        # Mock response when ML libraries aren't available
        return "Hello TEDDY, I'm feeling happy today!", 0.95
    
    model = get_whisper_model()
    if model is None:
        return "", 0.0
    
    # Write content to temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".mp3") as tmp:
        tmp.write(content)
        tmp_path = tmp.name
    
    try:
        segments, info = model.transcribe(tmp_path, language=None)
        text_parts = []
        for seg in segments:
            text_parts.append(seg.text)
        transcript = " ".join(t.strip() for t in text_parts).strip()
        confidence = float(getattr(info, "language_probability", 1.0))
        return transcript, confidence
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

def classify_text_emotion(text: str) -> Tuple[str, List[str], List[str], float]:
    """Classify emotion from text using keyword matching"""
    if not text:
        return ("none", [], [], 0.0)
    
    t = text.lower().strip()
    matched: Dict[str, List[str]] = {}

    for emotion, keywords in EMOTION_KEYWORDS.items():
        hits: List[str] = []
        for kw in keywords:
            # Match whole words or phrases
            pattern = r"\b" + re.escape(kw.lower()) + r"\b"
            if re.search(pattern, t):
                hits.append(kw)
        if hits:
            matched[emotion] = hits

    if not matched:
        return ("none", [], [], 0.0)

    # Sort candidates by priority
    candidates = list(matched.keys())
    candidates_sorted = sorted(
        candidates,
        key=lambda e: (
            EMOTION_PRIORITY.index(e) if e in EMOTION_PRIORITY else 999, 
            -len(matched[e])
        )
    )
    top = candidates_sorted[0]
    return (top, matched[top], candidates_sorted, 1.0)

# API Routes
@emotion_bp.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "ok",
        "ml_available": ML_AVAILABLE,
        "timestamp": datetime.now().isoformat()
    })

@emotion_bp.route('/analyze/image', methods=['POST'])
def analyze_image():
    """Analyze emotion in uploaded PNG image"""
    if not verify_api_key():
        return jsonify({"error": "Invalid or missing API key"}), 401
    
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    # Check file type
    if not file.content_type or not file.content_type.startswith('image/'):
        return jsonify({"error": "Only image files are supported"}), 415
    
    try:
        content = file.read()
        result = analyze_image_content(content)
        return jsonify(result)
    except Exception as e:
        current_app.logger.error(f"Error analyzing image: {str(e)}")
        return jsonify({"error": "Failed to analyze image"}), 500

@emotion_bp.route('/analyze/audio', methods=['POST'])
def analyze_audio():
    """Analyze emotion in uploaded MP3 audio"""
    if not verify_api_key():
        return jsonify({"error": "Invalid or missing API key"}), 401
    
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    # Check file type
    valid_types = ("audio/mpeg", "audio/mp3", "audio/mpeg3", "audio/x-mpeg-3")
    is_mp3_file = (file.filename and file.filename.lower().endswith(".mp3"))
    
    if not (file.content_type in valid_types or is_mp3_file):
        return jsonify({"error": "Only MP3 audio files are supported"}), 415
    
    try:
        content = file.read()
        transcript, confidence = transcribe_mp3_content(content)
        emotion, matches, candidates, conf = classify_text_emotion(transcript)

        result = {
            "transcript": transcript,
            "emotion": emotion,
            "matches": matches,
            "all_candidates": candidates,
            "confidence": conf,
            "transcription_confidence": confidence
        }
        
        if not ML_AVAILABLE:
            result["mock"] = True
        
        return jsonify(result)
    except Exception as e:
        current_app.logger.error(f"Error analyzing audio: {str(e)}")
        return jsonify({"error": "Failed to analyze audio"}), 500

@emotion_bp.route('/analyze/text', methods=['POST'])
def analyze_text():
    """Analyze emotion in text"""
    if not verify_api_key():
        return jsonify({"error": "Invalid or missing API key"}), 401
    
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({"error": "No text provided"}), 400
    
    try:
        text = data['text']
        emotion, matches, candidates, confidence = classify_text_emotion(text)
        
        return jsonify({
            "text": text,
            "emotion": emotion,
            "matches": matches,
            "all_candidates": candidates,
            "confidence": confidence
        })
    except Exception as e:
        current_app.logger.error(f"Error analyzing text: {str(e)}")
        return jsonify({"error": "Failed to analyze text"}), 500

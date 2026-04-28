"""Unit tests for predict.py — Predictor model loading and classification logic."""
 
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
 
import unittest
from unittest.mock import patch, MagicMock
import numpy as np
 
 
def make_predictor():
    """Helper to create a Predictor with mocked model and label encoder."""
    with patch('predict.joblib.load') as mock_load, \
         patch('predict.os.path.exists', return_value=True), \
         patch('predict.shap.TreeExplainer'):
 
        mock_model = MagicMock()
        mock_model.feature_names_in_ = [f'feature_{i}' for i in range(70)]
 
        mock_encoder = MagicMock()
        mock_encoder.classes_ = np.array([
            'BENIGN', 'Bot', 'DDoS', 'DoS GoldenEye', 'DoS Hulk',
            'DoS Slowhttptest', 'DoS Slowloris', 'FTP-Patator',
            'Other Attack', 'PortScan', 'SSH-Patator',
            'Web Attack - Brute Force', 'Web Attack - XSS'
        ])
 
        mock_load.side_effect = [mock_model, mock_encoder]
 
        from predict import Predictor
        predictor = Predictor()
        predictor.model = mock_model
        predictor.encoder = mock_encoder
        return predictor
 
 
DUMMY_FEATURES = [0.0] * 70
 
 
class TestPredictThreshold(unittest.TestCase):
 
    def test_high_confidence_benign_returned_as_benign(self):
        """If BENIGN confidence is above 50%, flow should be classified as BENIGN."""
        predictor = make_predictor()
 
        # BENIGN at index 0 with 90% confidence
        probs = np.zeros(13)
        probs[0] = 0.90  # BENIGN
        probs[2] = 0.05  # DDoS
 
        predictor.model.predict_proba = MagicMock(return_value=[probs])
 
        label, confidence = predictor.predict(DUMMY_FEATURES)
        self.assertEqual(label, 'BENIGN')
        self.assertAlmostEqual(confidence, 90.0)
 
    def test_low_benign_high_attack_returns_attack(self):
        """If BENIGN is below 50% and an attack class is above 50%, return the attack."""
        predictor = make_predictor()
 
        probs = np.zeros(13)
        probs[0] = 0.30  # BENIGN below threshold
        probs[9] = 0.65  # PortScan above threshold
 
        predictor.model.predict_proba = MagicMock(return_value=[probs])
 
        label, confidence = predictor.predict(DUMMY_FEATURES)
        self.assertEqual(label, 'PortScan')
        self.assertAlmostEqual(confidence, 65.0)
 
    def test_low_benign_low_attack_defaults_to_benign(self):
        """If BENIGN is below 50% but no attack class exceeds 50%, default to BENIGN."""
        predictor = make_predictor()
 
        probs = np.zeros(13)
        probs[0] = 0.35   # BENIGN below threshold
        probs[2] = 0.40   # DDoS also below threshold
        probs[4] = 0.25   # DoS Hulk also below threshold
 
        predictor.model.predict_proba = MagicMock(return_value=[probs])
 
        label, confidence = predictor.predict(DUMMY_FEATURES)
        self.assertEqual(label, 'BENIGN')
        self.assertAlmostEqual(confidence, 35.0)
 
    def test_returns_highest_confidence_attack(self):
        """When multiple attack classes exceed 50%, the highest confidence one is returned."""
        predictor = make_predictor()
 
        probs = np.zeros(13)
        probs[0] = 0.10   # BENIGN very low
        probs[2] = 0.55   # DDoS above threshold
        probs[9] = 0.35   # PortScan below threshold
 
        predictor.model.predict_proba = MagicMock(return_value=[probs])
 
        label, confidence = predictor.predict(DUMMY_FEATURES)
        self.assertEqual(label, 'DDoS')
        self.assertAlmostEqual(confidence, 55.0)
 
 
class TestIsAttack(unittest.TestCase):
 
    def test_benign_is_not_attack(self):
        """BENIGN label should return False from is_attack."""
        predictor = make_predictor()
        self.assertFalse(predictor.is_attack('BENIGN'))
 
    def test_attack_label_is_attack(self):
        """Any non-BENIGN label should return True from is_attack."""
        predictor = make_predictor()
        self.assertTrue(predictor.is_attack('PortScan'))
        self.assertTrue(predictor.is_attack('DDoS'))
        self.assertTrue(predictor.is_attack('SSH-Patator'))
 
    def test_error_label_is_not_attack(self):
        """Error label should return False from is_attack."""
        predictor = make_predictor()
        self.assertFalse(predictor.is_attack('Error'))
 
 
class TestPredictErrorHandling(unittest.TestCase):
 
    def test_predict_returns_error_on_exception(self):
        """If predict_proba raises an exception, predict should return Error and 0.0 confidence."""
        predictor = make_predictor()
        predictor.model.predict_proba = MagicMock(side_effect=Exception("Model failure"))
 
        label, confidence = predictor.predict(DUMMY_FEATURES)
        self.assertEqual(label, 'Error')
        self.assertEqual(confidence, 0.0)
 
 
if __name__ == '__main__':
    unittest.main(verbosity=2)
 
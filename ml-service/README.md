# ML Model Directory

This directory will contain the trained machine learning model.

## Model File
- `rf_model.pkl` - Trained Random Forest model (to be generated)

## Training
Run the training script to generate the model:
```bash
python training/train_model.py
```

## Model Details
- **Type**: Random Forest Classifier
- **Features**: 41 network traffic features from NSL-KDD dataset
- **Target**: Binary classification (Normal vs Malicious)
- **Expected Accuracy**: >95%

The model file will be created after running the training script in Week 3-4 of the implementation plan.
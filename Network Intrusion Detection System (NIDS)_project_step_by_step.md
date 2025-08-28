
# Network Intrusion Detection System (NIDS) — Step-by-step project guide

**Objective:** Build a machine-learning based NIDS that detects suspicious network activity using datasets such as NSL‑KDD or CIC‑IDS. This guide walks you from setup to model deployment.

---

## 1. Project overview
You will:
- Download a labeled intrusion dataset (NSL‑KDD or CIC‑IDS).
- Clean and explore the data (EDA).
- Train ML models (Random Forest, SVM).
- Evaluate models using precision/recall/F1 and confusion matrices.
- Optionally deploy a simple prediction API.

---

## 2. Prerequisites
- Python 3.8+
- Recommended libraries (see `requirements.txt` below)
- Optional: Docker for containerized deployment

**requirements.txt**
```
pandas
numpy
scikit-learn
matplotlib
seaborn
imbalanced-learn
joblib
scapy    # optional, for live packet capture/parsing
flask    # optional, for simple API
```

---

## 3. Datasets (where to get them)
- **NSL‑KDD** — cleaned benchmark of KDD'99 (mirrors available on Kaggle / Hugging Face). Use the CSV versions for easier loading. See Kaggle/Hugging Face for downloads. citeturn0search0turn0search26  
- **CIC‑IDS2017 / CSE‑CIC‑IDS2018** — realistic PCAP + flow-based CSVs provided by the Canadian Institute for Cybersecurity (UNB). These datasets include flow features extracted by CICFlowMeter and are suitable for flow-based IDS. citeturn0search1turn0search2

Tip: If working on a laptop or limited disk, prefer NSL‑KDD or selected CSV slices of CIC‑IDS rather than entire PCAPs.

---

## 4. Folder structure
```
nids-project/
├─ data/                # raw CSVs or downloaded datasets
├─ notebooks/           # EDA & experiments
├─ src/
│   ├─ preprocess.py
│   ├─ train.py
│   └─ api.py
├─ models/
├─ requirements.txt
└─ README.md
```

---

## 5. Step 1 — Load data (example: NSL-KDD CSV)
```python
import pandas as pd

# example: adjust path to your CSV
df = pd.read_csv('data/NSL-KDD/KDDTrain+.txt', header=None)
# if Kaggle copies provide column names, use those; otherwise map using the NSL-KDD feature list.
print(df.shape)
df.head()
```

For CIC‑IDS CSVs use `pd.read_csv('data/CIC-IDS-2017/Friday-02-03-2017_TrafficForML.csv')` (filenames vary).

---

## 6. Step 2 — Preprocessing
- Replace textual labels with numeric classes (e.g., `normal` -> 0, `attack` -> 1 or map attack types).
- Convert categorical features (protocol_type, service, flag) with `pd.get_dummies` or `sklearn.preprocessing.OneHotEncoder`.
- Handle missing/inf values (`df.replace([np.inf, -np.inf], np.nan).dropna()` or imputation).
- Scale numeric features with `StandardScaler` for SVM.

```python
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

# Assume X (features) and y (label) are prepared
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)
```

Dealing with **class imbalance**: use `imblearn.over_sampling.SMOTE` or class-weighted models.

---

## 7. Step 3 — Exploratory Data Analysis (EDA)
Plot class balance, attack counts, feature correlations.

```python
import matplotlib.pyplot as plt
import seaborn as sns

sns.countplot(x='label', data=df)           # class balance
plt.title('Class distribution')
plt.show()

corr = df.corr()
plt.figure(figsize=(10,8))
sns.heatmap(corr, vmax=0.8)
plt.show()
```

Look for highly correlated features and redundant columns.

---

## 8. Step 4 — Feature selection
Start with all features, then use:
- `SelectKBest` with `mutual_info_classif`
- Tree-based feature importance (RandomForest `.feature_importances_`)

```python
from sklearn.feature_selection import SelectKBest, mutual_info_classif

selector = SelectKBest(mutual_info_classif, k=30)
X_sel = selector.fit_transform(X_train, y_train)
```

---

## 9. Step 5 — Model training examples

### Random Forest
```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

rf = RandomForestClassifier(n_estimators=200, random_state=42, class_weight='balanced')
rf.fit(X_train, y_train)

pred = rf.predict(X_test)
print(classification_report(y_test, pred))
```

### SVM (may be slow on large datasets)
```python
from sklearn.svm import SVC
svm = SVC(kernel='rbf', C=1.0, class_weight='balanced', probability=True)
svm.fit(X_train, y_train)
```

---

## 10. Step 6 — Hyperparameter tuning
Use `GridSearchCV` or `RandomizedSearchCV` with cross-validation.

```python
from sklearn.model_selection import GridSearchCV

param_grid = {'n_estimators':[100,200], 'max_depth':[None,20,50]}
g = GridSearchCV(RandomForestClassifier(random_state=42), param_grid, cv=3, scoring='f1_macro', n_jobs=-1)
g.fit(X_train, y_train)
print(g.best_params_)
```

---

## 11. Step 7 — Evaluation
- Use `classification_report` for precision/recall/F1 (macro and weighted).
- For binary tasks compute ROC AUC. For multiclass, use one-vs-rest ROC or per-class AUC.
- Plot confusion matrix.

```python
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.metrics import ConfusionMatrixDisplay

ConfusionMatrixDisplay.from_predictions(y_test, pred)
plt.show()
```

Interpret results considering class imbalance — prefer precision/recall over raw accuracy.

---

## 12. Step 8 — Save model & scaler
```python
import joblib
joblib.dump(rf, 'models/rf_nids.joblib')
joblib.dump(scaler, 'models/scaler.joblib')
```

---

## 13. Step 9 — Simple prediction API (Flask)
```python
# src/api.py
from flask import Flask, request, jsonify
import joblib
import numpy as np

app = Flask(__name__)
model = joblib.load('models/rf_nids.joblib')
scaler = joblib.load('models/scaler.joblib')

@app.route('/predict', methods=['POST'])
def predict():
    payload = request.json
    # payload should be a list of feature vectors
    X = np.array(payload['instances'])
    X = scaler.transform(X)
    preds = model.predict(X)
    return jsonify({'predictions': preds.tolist()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

Pack into Docker if desired.

---

## 14. Step 10 — Deployment ideas
- Dockerize the Flask app and serve behind Gunicorn + Nginx.
- Stream features from a network collector (Bro/Zeek, CICFlowMeter) into your predictor.
- For high-throughput, use batching and asynchronous workers (Celery or Kafka).

---

## 15. Extensions / Next steps
- Use deep learning (LSTM/CNN) on packet/flow sequences.
- Online learning (scikit-multiflow, river) for concept drift.
- Create an alerting pipeline that pushes to SIEM (Elastic Stack).

---

## 16. Reproducible experiments & suggestions
- Keep a `notebooks/` directory with EDA and model checkpoints.
- Log experiments (MLflow or simple CSV logs).
- Use `random_state` everywhere to make results reproducible.

---

## 17. References & example repos
- CIC‑IDS datasets (UNB) and docs. citeturn0search1turn0search2  
- Example GitHub analysis for CICIDS2017 and NSL‑KDD. citeturn0search12turn0search18

---

## Appendix: How to run (quick)
1. Create and activate venv:
```
python -m venv venv
source venv/bin/activate    # Windows: venv\\Scripts\\activate
pip install -r requirements.txt
```
2. Put dataset CSVs in `data/`.
3. Run `python src/preprocess.py` then `python src/train.py`.
4. Start API: `python src/api.py`.

---

If you want, I can also:
- provide ready-to-run `preprocess.py` and `train.py` files,
- produce a Jupyter notebook with EDA + model training,
- or create a Dockerfile + `docker-compose.yml` for deployment.


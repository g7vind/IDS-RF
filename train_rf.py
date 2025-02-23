import os
import pandas as pd
import numpy as np
import joblib
from tqdm import tqdm
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, classification_report

# Set dataset path
dataset_folder = "/content/drive/MyDrive/dataset"  # Update path if needed
all_files = os.listdir(dataset_folder)
csv_files = [f for f in all_files if f.endswith('.csv')]

# Load and combine all CSVs
df_list = []
for file in tqdm(csv_files, desc="Loading CSVs"):
    file_path = os.path.join(dataset_folder, file)
    df = pd.read_csv(file_path)
    df_list.append(df)

df_combined = pd.concat(df_list, ignore_index=True)
df_combined.rename(columns=lambda x: x.strip(), inplace=True)

# Remove unnamed columns
df_combined = df_combined.loc[:, ~df_combined.columns.str.contains('^Unnamed')]

# Handle missing values
df_combined.replace([np.inf, -np.inf], np.nan, inplace=True)  # Replace inf values
df_combined.fillna(0, inplace=True)  # Fill NaNs with 0

# Encode labels
if "Label" in df_combined.columns:
    label_encoder = LabelEncoder()
    df_combined["Label"] = label_encoder.fit_transform(df_combined["Label"])
else:
    raise KeyError("❌ 'Label' column not found in dataset!")

# Split features and labels
X = df_combined.drop(columns=["Label"])
y = df_combined["Label"]

# Normalize data
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Train RandomForest model with progress bar
rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
print("\U0001F680 Training Random Forest Model...")
rf_model.fit(X_train, y_train)

# Predictions on training and testing data
y_train_pred = rf_model.predict(X_train)
y_test_pred = rf_model.predict(X_test)

# Compute accuracy
train_accuracy = accuracy_score(y_train, y_train_pred)
test_accuracy = accuracy_score(y_test, y_test_pred)

# Print accuracy results
print(f"✅ Training Accuracy: {train_accuracy * 100:.2f}%")
print(f"✅ Testing Accuracy: {test_accuracy * 100:.2f}%")

# Detailed classification report for testing data
print("\n🔍 Classification Report (Test Data):")
print(classification_report(y_test, y_test_pred))

# Save model, scaler, and encoder
model_dir = "/content/drive/MyDrive/models"
os.makedirs(model_dir, exist_ok=True)

joblib.dump(rf_model, os.path.join(model_dir, "random_forest_model.pkl"))
joblib.dump(scaler, os.path.join(model_dir, "scaler.pkl"))
joblib.dump(label_encoder, os.path.join(model_dir, "label_encoder.pkl"))

print(f"🎯 Model training complete! Model saved in: {model_dir}")

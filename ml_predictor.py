import joblib
import pandas as pd

def load_model():
    # This is where you specify the path for the model to be used
    MODEL_FILENAME = "gbrtModel1"
    return joblib.load(MODEL_FILENAME)

def make_prediction(df):
    model = load_model()
    to_predict = df.columns
    predicted = model.predict(df[to_predict])
    result = predicted[0]
    print(result)
    return result

if __name__ == "__main__":
  # This is where you specify the path to the artifact's csv.
  filename = "path_to_csv.csv"
  df = pd.read_csv(filename)
  make_prediction(df)
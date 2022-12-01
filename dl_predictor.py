import numpy as np
import tensorflow as tf
import pandas as pd
from tensorflow import keras
from tensorflow.keras.models import load_model
from tensorflow.keras.wrappers.scikit_learn import KerasClassifier


# This is where you load the actual saved model into new variable.
model_identifier = "326693495863495c8fa7b906c67af1df"
model2 = load_model("rnswr_model_"+model_identifier+".h")

def make_prediction(filename):
    df = pd.read_csv(filename)
    y_pred = model2.predict(df)
    predicted = np.argmax(y_pred,axis=1)[0]
    # 0 -> E, 1 -> G, 2 -> L
    prediction = ""
    if predicted == 0:
        prediction = "E"
    if predicted == 1:
        prediction = "G"
    if predicted == 2:
        prediction = "L"
    print(prediction)


if __name__ == "__main__":
    # This is where you can specify the path to the CSV file.
    make_prediction("path_to_csv.csv")

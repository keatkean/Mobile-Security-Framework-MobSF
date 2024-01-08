from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
import pandas as pd
from sklearn.model_selection import cross_val_score

def permissionScoring(csv_file: str, file_path: str):
    # Load data
    f = open(file_path,"r")
    content = f.read()
    f.close()

    # convert text to dataframe
    data_dict = eval(content)
    new_data = pd.DataFrame.from_dict(data_dict)
    df = pd.read_csv(csv_file)

    # ...
    # Assume 'Is_Malicious' is the column with your labels
    X = df.drop('is_malicious', axis=1)
    y = df['is_malicious']



    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)



    # Create and train model
    model = LogisticRegression()
    model.fit(X_train, y_train)

    # Make predictions
    y_pred = model.predict(X_test)
    scores = cross_val_score(model, X, y, cv=5)

    print(f'Cross-Validation Accuracy Scores: {scores}')
    print(f'Average Cross-Validation Accuracy: {scores.mean()}')

    # Evaluate model
    accuracy = accuracy_score(y_test, y_pred)

    model.fit(X_train, y_train)

    predictions = model.predict(new_data)
    return {'prediction': predictions[0], 'accuracy': accuracy}

def permissionMalwareType(file_path: str):
    capabilities = []

    logs = open(file_path, 'r').read().split('\n')
    for line in logs:
        if '[Permission] [*] Location based spyware' in line:
            capabilities.append('Spyware (Location)')
        elif '[Permission] [*] Camera based spyware' in line:
            capabilities.append('Spyware (Camera)')
        elif '[Permission] [*] Audio based spyware' in line:
            capabilities.append('Spyware (Audio)')
        elif '[Permission] [*] Message based spyware' in line:
            capabilities.append('Spyware (Message)')
        elif '[Permission] [*] Ransomeware capability' in line:
            capabilities.append('Ransomware')
        elif '[Permission] [*] Dropper capability' in line:
            capabilities.append('Dropper')

    return capabilities




    # # Drop the first unnamed column
    # df = df.drop(df.columns[0], axis=1)

    # # Correct column names
    # df.columns = df.columns.str.strip() # remove any leading/trailing spaces
    # cols = df.columns.tolist()
    # cols = cols[1:] + [cols[0]] # shift column names to the left
    # df.columns = cols

    # # Now 'is_malicious' should be the name of the last column
    # X = df.drop('is_malicious', axis=1)
    # y = df['is_malicious']

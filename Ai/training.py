import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import confusion_matrix, accuracy_score, classification_report
from sklearn.model_selection import cross_val_score


# Load the dataset
data = pd.read_csv('dataset.csv')
data = data.drop('id', axis='columns')
data = data.drop('SSLfinal_State', axis='columns')
data = data.drop('Page_Rank', axis='columns')
data = data.drop('Google_Index', axis='columns')
data = data.drop('Links_pointing_to_page', axis='columns')
data = data.drop('Statistical_report', axis='columns')

classes = Counter(data['Result'].values)
class_dist = pd.DataFrame(classes.most_common(), columns=['Class', 'Num_Observations'])
class_dist

# Split the dataset into features and Result
X = data.iloc[:,0:25]
y = data.iloc[:,25]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=np.random.seed(7))

rf = RandomForestClassifier()
rf.fit(X_train, y_train)


# Perform 5-fold cross validation
scores = cross_val_score(rf, X, y, cv=5)

# Print the mean score and the 95% confidence interval
print("Accuracy: %0.2f (+/- %0.2f)" % (scores.mean(), scores.std() * 2))

print(classification_report(y_test, rf.predict(X_test), target_names=['Phishing Websites', 'Normal Websites']))

# Generate predictions
y_pred = rf.predict(X_test)

# use the confusion matrix to extract true positives, false positives, true negatives, and false negatives
tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

# calculate the accuracy, precision, recall, and F1 score
accuracy = (tp + tn) / (tp + tn + fp + fn)
precision = tp / (tp + fp)
recall = tp / (tp + fn)
f1 = 2 * (precision * recall) / (precision + recall)

print(f'Accuracy: {accuracy}')
print(f'Precision: {precision}')
print(f'Recall: {recall}')
print(f'F1 Score: {f1}')

# Save the model
import joblib
joblib.dump(rf, 'model.pkl')
print("Model dumped!")
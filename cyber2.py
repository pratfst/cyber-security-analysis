import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import  train_test_split
from sklearn.metrics import accuracy_score
import pickle
from sklearn import metrics



fd = pd.read_csv('KDDTest+.txt', sep=',')

columns = (['durations'
,'protocol_type'
,'service'
,'flags'
,'src_bytes'
,'dst_bytes'
,'land'
,'wrong_fragment'
,'urgent'
,'hot'
,'num_failed_logins'
,'logged_in'
,'num_compromised'
,'root_shell'
,'su_attempted'
,'num_root'
,'num_file_creations'
,'num_shells'
,'num_access_files'
,'num_outbound_cmds'
,'is_host_login'
,'is_guest_login'
,'count'
,'srv_count'
,'serror_rate'
,'srv_serror_rate'
,'rerror_rate'
,'srv_rerror_rate'
,'same_srv_rate'
,'diff_srv_rate'
,'srv_diff_host_rate'
,'dst_host_count'
,'dst_host_srv_count'
,'dst_host_same_srv_rate'
,'dst_host_diff_srv_rate'
,'dst_host_same_src_port_rate'
,'dst_host_srv_diff_host_rate'
,'dst_host_serror_rate'
,'dst_host_srv_serror_rate'
,'dst_host_rerror_rate'
,'dst_host_srv_rerror_rate'
,'attack'
,'level'])

fd.columns = columns

ifattack = fd.attack.map(lambda a: 0 if a == 'normal' else 1)
fd['attack_label'] = ifattack

fd["protocol_type"] = fd["protocol_type"].map({ 'icmp':1,'tcp':2, 'udp':3})


fd1=fd.drop(["service","flags","land","wrong_fragment","urgent","hot","num_compromised","root_shell",
"su_attempted","num_root","num_file_creations","num_shells","num_access_files","num_outbound_cmds",
"count","srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
"diff_srv_rate","srv_diff_host_rate","dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
"dst_host_rerror_rate","dst_host_srv_rerror_rate","attack","level"],axis=1)

x=fd1.iloc[:,:9]
y=fd1.iloc[:,-1] 

x_train,x_test,y_train,y_test=train_test_split(x,y,train_size=0.8,random_state=28)

rf=RandomForestClassifier()


"""n_estimators = [5,20,50,100,200,500,1000] # number of trees in the random forest
max_features = ['auto', 'sqrt'] # number of features in consideration at every split
max_depth = [int(x) for x in np.linspace(10, 120, num = 12)] # maximum number of levels allowed in each decision tree
min_samples_split = [2, 6, 10, 14] # minimum sample number to split a node
min_samples_leaf = [1, 3, 4, 6] # minimum sample number that can be stored in a leaf node
bootstrap = [True, False] # method used to sample data points

random_grid = {'n_estimators': n_estimators,

'max_features': max_features,

'max_depth': max_depth,

'min_samples_split': min_samples_split,

'min_samples_leaf': min_samples_leaf,

'bootstrap': bootstrap}


from sklearn.model_selection import RandomizedSearchCV
rf_random = RandomizedSearchCV(estimator = rf,param_distributions = random_grid,
               n_iter = 100, cv = 5, verbose=2, random_state=35, n_jobs = -1)

rf_random.fit(x_train, y_train)"""

#print ('Best Parameters: ', rf_random.best_params_, ' \n')

rf=RandomForestClassifier(n_estimators=500, min_samples_split= 6, min_samples_leaf= 1, max_features= 'sqrt', max_depth= 50, bootstrap=False)
rf.fit(x_train,y_train)

prediction=rf.predict(x_test)

print("Accuracy of model  is:",accuracy_score(prediction,y_test))
Precision = metrics.precision_score(prediction, y_test)
print("Precision Score is :", Precision)
recall=metrics.recall_score(prediction, y_test)
print("Recall  Score is :", recall)
f1=metrics.f1_score(prediction, y_test)
print("F1  Score is :", f1)


pickle.dump(rf, open('cyber.pkl','wb'))

model = pickle.load( open('cyber.pkl','rb'))


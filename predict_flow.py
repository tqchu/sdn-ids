import pickle

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler

# df1 = pd.read_csv('metasploitable-2.csv')
# dos = df1[df1['Label'] == 'DoS']

features_col = [
    # "Src IP",
    # "Flow ID",
    # "Src Port",
    # "Dst IP",
    # "Dst Port",
    # "Protocol",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean",
    "Fwd Pkt Len Std",
    "Bwd Pkt Len Max",
    "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean",
    "Bwd Pkt Len Std",
    "Flow Byts/s",
    "Flow Pkts/s"
]

# features = {'total_src_ips': 1,
#             'flow_count': 97889,
#             'Tot Fwd Pkts': 97889,
#             'Tot Bwd Pkts': 0,
#             'TotLen Fwd Pkts': 4502894,
#             'TotLen Bwd Pkts': 0,
#             'Flow Pkts/s': 30982.355480663442,
#             'Flow Byts/s': 1425188.3521105184,
#             'Flow Duration': 5,
#             'total_pkts': 97889,
#             'total_bytes': 4502894,
#             'pkts_per_src_ip': 97889.0,
#             'bytes_per_src_ip': 4502894.0,
#         }

features = {'Flow ID': '198.51.100.1_0_198.51.100.128_0_1',
            'Src IP': '198.51.100.1',
            'Src Port': 0,
            'Dst IP': '198.51.100.128',
            'Dst Port': 0,
            'Protocol': 1,
            'Timestamp': 1750774401671782385,
            'Flow Duration': 2507953.0,
            'Tot Fwd Pkts': 30672,
            'Tot Bwd Pkts': 9347,
            'TotLen Fwd Pkts': 1410912,
            'TotLen Bwd Pkts': 429962,
            'Fwd Pkt Len Max': 46,
            'Fwd Pkt Len Min': 46,
            'Fwd Pkt Len Mean': 46.0,
            'Fwd Pkt Len Std': np.float64(0.0),
            'Bwd Pkt Len Max': 46,
            'Bwd Pkt Len Min': 46,
            'Bwd Pkt Len Mean': 46.0,
            'Bwd Pkt Len Std': np.float64(0.0),
            'Flow Byts/s': 734014.5529043009,
            'Flow Pkts/s': 15956.838106615234}

with open('models/best_flow_model.pkl',
          'rb') as f:
    mlp_model = pickle.load(f)

with open('models/flow_scaler.pkl',
          'rb') as f:
    scaler = pickle.load(f)

X1 = pd.DataFrame([features], columns=features_col)

X1 = scaler.transform(X1)
y_mlp = mlp_model.predict(X1)
print("y_mlp", y_mlp)
#
# with open('randomforest_model.pkl',
#           'rb') as f:
#     randomforest_model = pickle.load(f)
#
# y_randomforest = randomforest_model.predict(X1)
# print("y_randomforest", y_randomforest)
#
# with open('svm_model.pkl',
#           'rb') as f:
#     svm_model = pickle.load(f)
#
# y_svm_model = svm_model.predict(X1)
# print("y_svm_model", y_svm_model)
#
# with open('gradientboosting_model.pkl',
#           'rb') as f:
#     gradientboosting_model = pickle.load(f)
#
# y_gradientboosting_model = gradientboosting_model.predict(X1)
# print("y_gradientboosting_model", y_gradientboosting_model)
#
# # X2= dos[features_col]
# # X2 = scaler.transform(X2)
# # y2 = model.predict(X2)
# # correct = 0
# # for idx , yi in enumerate(y2):
# #
# #     if yi == 'DoS':
# #         correct += 1
# #         print("Correct idx", dos[features_col].iloc[idx])
# #
# # print("Accuracy", correct/len(y2))

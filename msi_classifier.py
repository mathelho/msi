# -*- coding: utf-8 -*-
"""MSI - Classifier

Automatically generated by Colab.

Original file is located at
    https://colab.research.google.com/drive/1Znl-ZQl6Y8NUBH9PsdNL9R6baVCfuSFw

Importando as bibliotecas principais:
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score, classification_report, precision_score, recall_score

"""Instalando o gdown para baixar arquivos do Google Drive (neste caso, vamos fazer o download do arquivo csv):"""

!pip install gdown

import gdown

"""Download do arquivo:"""

url = "https://drive.google.com/u/1/uc?id=1DEJpczRY0AtIDcVjCo8FZXIi3sarxgwv&export=download"
output = 'df_total.csv'
gdown.download(url, output, quiet=False)

"""Mostrando as primeiras linhas do dataset:"""

df = pd.read_csv('df_total.csv')
df.head()

df.info()

"""Transformando os valores da coluna device_src_name em inteiros:"""

le = LabelEncoder()

for i in df.columns:
  le = LabelEncoder()
  df[i] = le.fit_transform(df[i].values)

df

"""Separando a coluna que vamos classificar em um dataset isolado, contendo apenas esta coluna:"""

df_x = df.drop('device_src_name', axis=1)
df_y = df['device_src_name']

df_y

X_train, X_test, y_train, y_test = train_test_split(df_x, df_y, random_state=0, test_size=0.3)
print('Número de casos de treino: ', X_train.shape[0])
print('Número de casos de teste: ', X_test.shape[0])

"""Usando classificador Decision Tree:"""

from sklearn.tree import DecisionTreeClassifier
dt_model = DecisionTreeClassifier().fit(X_train, y_train)

dt_predictions = dt_model.predict(X_test)
print('Acurácia do modelo: ', accuracy_score(y_test, dt_predictions))

print('Classification Report'.center(70, '='))
print(classification_report(y_test, dt_predictions))

print('Matriz de confusão'.center(70, '='))
print(confusion_matrix(y_test, dt_predictions))

"""Usando MLP:"""

from sklearn.neural_network import MLPClassifier
mlp = MLPClassifier(hidden_layer_sizes=(64,32), max_iter=1000, random_state=0)

mlp.fit(X_train, y_train)
mlp_predictions = mlp.predict(X_test)

print('Acurácia: ', accuracy_score(y_test, mlp_predictions))

"""Usando Random Forest:"""

from sklearn.ensemble import RandomForestClassifier
rf = RandomForestClassifier()

rf.fit(X_train, y_train)
rf_pred = rf.predict(X_test)

accuracy = accuracy_score(y_test, rf_pred)
print('Acurácia: ', accuracy)

"""Usando regressão logística (com parâmetros que permitem usar este modelo na versão multinomial/multiclasse:"""

from sklearn.linear_model import LogisticRegression
lr = LogisticRegression(multi_class='multinomial', solver='lbfgs', max_iter=1000)

lr.fit(X_train, y_train)
lr_pred = lr.predict(X_test)

accuracy = accuracy_score(y_test, lr_pred)
print('Acurácia: ', accuracy)

"""Usando K-Neighbors:"""

from sklearn.neighbors import KNeighborsClassifier
kn = KNeighborsClassifier(n_neighbors=2, metric='euclidean')

kn.fit(X_train, y_train)
kn_pred = kn.predict(X_test)

accuracy = accuracy_score(y_test, kn_pred)
print('Acurácia: ', accuracy)

"""Verificando os diferentes valores de K no K-Neighbors. De acordo com o gráfico, nos nossos dados, a acurácia do modelo tende a abaixar conforme o valor de K aumenta."""

acc = {}

for k in range(3, 30, 2):
  kn = KNeighborsClassifier(n_neighbors=k, metric='euclidean')
  kn.fit(X_train, y_train)

  kn_pred = kn.predict(X_test)
  acc[k] = accuracy_score(y_test, kn_pred)

plt.plot(range(3, 30, 2), acc.values())
plt.xlabel('K')
plt.ylabel('Acurácia')
plt.show()

"""Usando o Perceptron:"""

from sklearn.linear_model import Perceptron
p_model = Perceptron(max_iter=100, eta0=0.1, random_state=42)

p_model.fit(X_train, y_train)
p_pred = p_model.predict(X_test)

accuracy = accuracy_score(y_test, p_pred)
print('Acurácia: ', accuracy)

"""Testando redes neurais..."""

import keras
from keras.models import Sequential
from keras.layers import Dense

model = Sequential()
# primeira camada, utilizando a função de ativação ReLU e 4 colunas (mesmo número de colunas do nosso dataframe X)
model.add(Dense(100, activation='relu', input_shape=(4,)))
# segunda camada, usando 22 pois o maior número na coluna Y (das labels) é 21. softmax é uma função de ativação para classificação multi-classe
model.add(Dense(22, activation='softmax'))

# compilando o modelo. primeiramente tentei usar categorical_crossentropy como a função de perda, mas apresentou erro. funcionou com a sparse
model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])

model.fit(X_train, y_train, batch_size=128, epochs=10, validation_split=0.1)

perda, acuracia = model.evaluate(X_test, y_test)

print(f"Perda no teste: {perda}, Acurácia no teste: {acuracia}")

"""Mais uma rede neural, testando outros tipos de camadas:"""

model_2 = Sequential()
model_2.add(Dropout(0.2, input_shape=(4,)))
model_2.add(Dense(100, activation='relu'))

model_2.add(Dense(22,))
model_2.add(BatchNormalization())
model_2.add(Activation('softmax'))

model_2.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])

model_2.fit(X_train, y_train, batch_size=128, epochs=10, validation_split=0.1)

perda, acuracia = model_2.evaluate(X_test, y_test)

print(f"Perda no teste: {perda}, Acurácia no teste: {acuracia}")
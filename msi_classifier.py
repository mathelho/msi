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
from tqdm import tqdm
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score, classification_report, precision_score, recall_score
import keras
from keras.models import Sequential
from keras.layers import Dense, Dropout, Activation, BatchNormalization, Conv1D, Flatten, Reshape
from tensorflow.keras.losses import MSE
import tensorflow as tf

"""Instalando o gdown para baixar arquivos do Google Drive (neste caso, vamos fazer o download do arquivo csv):"""

!pip install gdown

import gdown

"""Download do arquivo:"""

url = "https://drive.google.com/u/1/uc?id=1F8jSkzJ4raeCzcqptyC1C51QdmmAEY4Q&export=download"
output = 'df_total.csv'
gdown.download(url, output, quiet=False)

"""Mostrando as primeiras linhas do dataset:"""

df = pd.read_csv('df_total.csv')
df.head()

df.info()

"""Removendo as colunas de endereço MAC, pois não são interessantes para o treinamento do modelo."""

#df = df.drop('mac_src', axis=1)
#df = df.drop('mac_dst', axis=1)
#df.head()

"""Calculando medidas estatísticas para as colunas de "timestamp" e "len", de forma a termos mais características no dataset. Features como endereço MAC, IP e porta são consideradas invasivas, podendo ocasionar em invasão de privacidade. Timestamp e tamanho do pacote são features passivas e se encaixam melhor neste processo."""

def statistical_features_by_day_perPacket(df_total):

	"""
	Manipulacao dos dados para extracao de medidas estatisticas no nivel de pacote
	Organizacao de saidas para os plots dos graficos
	Para cada grupo de device extrai um subgrupo
	"""
	#print(df_total.columns)
	devicegroup = df_total.groupby(['device_src_name'])

	all_devices_samples = []
	for name, amostra in tqdm(devicegroup, unit = "device"): # tqdm = progress bar
		if (len(amostra.index) > 2):

			# use for plots
			#SAMPLERANGE = len(amostra)
			#amostras_tamanho_x = np.array_split(amostra, len(amostra)/SAMPLERANGE)
			# use for ML algorithms
			amostras_tamanho_x = np.array_split(amostra, len(amostra)/3)

			for device in amostras_tamanho_x:
				#print(device)

				device = pd.DataFrame(device)

				all_devices_samples.append(
					pd.DataFrame(data={
					# ['ip_src', 'ip_dst', 'proto', 'timestamp', 'mac_src', 'mac_dst', 'len', 'src_port', 'dst_port', 'device']

					"device_name": [str(device["device_src_name"].values[0])],
					#"n_packets":  [device['device_src_name'].count()],
					"mean_n_bytes": [device['len'].mean()],
					"stdev_n_bytes": [device['len'].std(ddof=0)],
					#"min_n_bytes": [device['len'].min()],
					#"max_n_bytes": [device['len'].max()],
					#"sum_n_bytes": [device['len'].sum()],
					"median_n_bytes": [device['len'].median()],
					"mean_timestamp": [device['timestamp'].mean()],
					"stdev_timestamp": [device['timestamp'].std(ddof=0)],
					#"sum_timestamp": [device['timestamp'].sum()],
					"median_timestamp": [device['timestamp'].median()],
					#"min_timestamp": [device['timestamp'].min()],
					#"max_timestamp": [device['timestamp'].max()],
          }))

	all_devices_samples = pd.concat(all_devices_samples)

	## salva o df aqui #####
	#all_devices_samples.to_csv(PACKETPLOTSDIR + (file.split('/')[-1]), index=False)
	#print('done writing statistical features to : ' + PACKETPLOTSDIR + (file.split('/')[-1]))

	return all_devices_samples

#df = statistical_features_by_day_perPacket(df)
#df.head()

#df.to_csv('df_statistic.csv', index=False)

"""Transformando os valores da coluna device_src_name em inteiros:"""

le = LabelEncoder()

df['device_name'] = le.fit_transform(df['device_name'].values)

df

"""Separando a coluna que vamos classificar em um dataset isolado, contendo apenas esta coluna:"""

df_x = df.drop('device_name', axis=1)
df_y = df['device_name']

df_y

X_train, X_test, y_train, y_test = train_test_split(df_x, df_y, random_state=42, test_size=0.3)
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

#from sklearn.linear_model import LogisticRegression
#lr = LogisticRegression(multi_class='multinomial', solver='lbfgs', max_iter=1000)

#lr.fit(X_train, y_train)
#lr_pred = lr.predict(X_test)

#accuracy = accuracy_score(y_test, lr_pred)
#print('Acurácia: ', accuracy)

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

# linha abaixo corrige o erro 'TensorFlow is executing eagerly. Please disable eager execution.' e 'maximum recursion depth exceeded'
tf.compat.v1.disable_eager_execution()

"""Testando redes neurais..."""

model = Sequential()
# primeira camada, utilizando a função de ativação ReLU e 4 colunas (mesmo número de colunas do nosso dataframe X)
model.add(Dense(100, activation='relu', input_shape=(6,)))
# segunda camada, usando 22 pois o maior número na coluna Y (das labels) é 21. softmax é uma função de ativação para classificação multi-classe
model.add(Dense(22, activation='softmax'))

# compilando o modelo. primeiramente tentei usar categorical_crossentropy como a função de perda, mas apresentou erro. funcionou com a sparse
model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])

model.fit(X_train, y_train, batch_size=128, epochs=10, validation_split=0.1)

perda, acuracia = model.evaluate(X_test, y_test)

print(f"Perda no teste: {perda}, Acurácia no teste: {acuracia}")

"""Mais uma rede neural, testando outros tipos de camadas:"""

model_2 = Sequential()
model_2.add(Dropout(0.2, input_shape=(6,)))
model_2.add(Dense(100, activation='relu', input_shape=(6,)))

model_2.add(Dense(22,))
model_2.add(BatchNormalization())
model_2.add(Activation('softmax'))

model_2.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])

model_2.fit(X_train, y_train, batch_size=128, epochs=10, validation_split=0.1)

perda, acuracia = model_2.evaluate(X_test, y_test)

print(f"Perda no teste: {perda}, Acurácia no teste: {acuracia}")

"""Mesmas camadas mas com outros parâmetros?"""

model_3 = Sequential()
model_3.add(Dropout(0.2, input_shape=(6,)))
model_3.add(Dense(100, activation='relu'))

model_3.add(Dense(22,))
model_3.add(BatchNormalization())
model_3.add(Activation('softmax'))

model_3.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])

model_3.fit(X_train, y_train, batch_size=50, epochs=15, validation_split=0.1)

perda, acuracia = model_3.evaluate(X_test, y_test)

print(f"Perda no teste: {perda}, Acurácia no teste: {acuracia}")

"""Mais camadas, usando flatten... não melhorou"""

model_4 = Sequential()
model_4.add(Dropout(0.2, input_shape=(4,)))
model_4.add(Dense(100, activation='relu'))
model_4.add(Dense(64, activation='relu'))

model_4.add(Flatten())
model_4.add(Dense(200,))
model_4.add(Dense(100,))
model_4.add(BatchNormalization())
model_4.add(Activation('softmax'))

model_4.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])

model_4.fit(X_train, y_train, batch_size=128, epochs=10, validation_split=0.1)

perda, acuracia = model_4.evaluate(X_test, y_test)

print(f"Perda no teste: {perda}, Acurácia no teste: {acuracia}")

"""Iniciando com modelos adversariais, utilizando o método FGSM:"""

def generate_adversary(model, image, label, eps=2 / 255.0):
  image = tf.cast(image, tf.float32)

  with tf.GradientTape() as tape:
    tape.watch(image)

    pred = model(image)
    loss = MSE(label, pred)

    gradient = tape.gradient(loss, image)
    signedGrad = tf.sign(gradient)

    adversary = (image + (signedGrad * eps)).numpy()

    return adversary

y_test.iloc[0]

for i in np.random.choice(np.arange(0, len(X_test)), size=(10,)):
  image = X_test.iloc[i]
  label = y_test.iloc[i]

  adversary = generate_adversary(model_2, image.values.reshape(1, 4), label, eps=0.1)

  pred = model_2.predict(adversary)

pred

pip install adversarial-robustness-toolbox

#pip install scikeras

# https://embracethered.com/blog/posts/2020/husky-ai-adversarial-robustness-toolbox-testing/
# https://github.com/Trusted-AI/adversarial-robustness-toolbox/issues/1977
# https://stackoverflow.com/questions/53676883/dnnclassifier-dataframe-object-has-no-attribute-dtype
from art.attacks.evasion import FastGradientMethod
from art.estimators.classification import KerasClassifier

art_classifier = KerasClassifier(model=model_2, use_logits=False)  ## modelo é o modelo treinado que faz o model.fit()

attack = FastGradientMethod(estimator=art_classifier, eps=0.8) ## brincar com o eps
x_test_fgsm = attack.generate(x=X_test.values)
print(x_test_fgsm)

x_test_fgsm.shape

df_fgsm = pd.DataFrame(x_test_fgsm, columns=X_test.columns)
df_fgsm

X_test

pred_fgsm = np.argmax(model_2.predict(df_fgsm), axis=1)

print(pred_fgsm)

df_test = pd.DataFrame(pred_fgsm)
print(df_test[0].value_counts())

# https://stackoverflow.com/questions/71874695/valueerror-classification-metrics-cant-handle-a-mix-of-multiclass-and-continuo
acuracia_fgsm = accuracy_score(y_test, pred_fgsm)
print('Acuracia: ', acuracia_fgsm)
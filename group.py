import numpy as np
import pandas as pd

df = pd.read_csv('df_total.csv')
df.head()

df1 = df.copy()
N = 3

grp_cols = ['device_src_name']
df1 = df1.groupby([
    *grp_cols, df1.groupby(grp_cols).cumcount() // N
], sort=False).sum(numeric_only=True).droplevel(-1).reset_index()

df1 = df1.sort_values(by=['device_src_name'])
df1.to_csv('df_stats.csv', index=False)
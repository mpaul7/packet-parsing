import hashlib
import pandas as pd

class FlowMapper:
    """Maps flows between different dataframes based on hash"""
    
    def _add_hash_column(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add flow hash column to dataframe"""
        df = df.astype({'sport': int, 'dport': int, 'protocol': int})
        
        def calculate_flow_hash(row):
            m = hashlib.md5()
            hash_str = ''.join([str(row.sip), str(row.sport), 
                                str(row.dip), str(row.dport), 
                                str(row.protocol)])
            m.update(hash_str.encode())
            return m.hexdigest()
            
        df['hash'] = [calculate_flow_hash(row) for _, row in df.iterrows()]
        return df
        
    def map(self, df_features: pd.DataFrame, df_labels: pd.DataFrame,
            with_timestamp: bool = True) -> pd.DataFrame:
        """Map features between dataframes using flow hash"""
        df_fea = self._add_hash_column(df_features)
        df_label = self._add_hash_column(df_labels)

        keys = ["sip", "sport", "dip", "dport", "protocol", "first_timestamp_ms"]
        if not with_timestamp:
            keys = keys[:-1]
        else:
            df_fea['first_timestamp_ms'] = df_fea['first_timestamp'] // 1000  # convert first timestamp to ms

        df_fea['id'] = df_fea[keys].apply(lambda row: '_'.join(row.values.astype(str)), axis=1)
        df_label['id'] = df_label[keys].apply(lambda row: '_'.join(row.values.astype(str)), axis=1)
        df = df_fea.merge(df_label, how='left', on='hash', suffixes=('', '_y'))
        df = df.drop([col for col in df.columns if col.endswith('_y')], axis=1)  # drop nfs key columns
        df = df.drop(columns=['id'])  # drop id calculation columns
        return df

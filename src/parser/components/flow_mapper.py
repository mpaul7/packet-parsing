import hashlib
import pandas as pd

class FlowMapper:
    """Maps flows between different dataframes based on hash"""
    
    def _add_hash_column(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add flow hash column to dataframe, robust to missing/NaN values."""
        df = df.copy()

        for col in ("sport", "dport", "protocol"):
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)
            else:
                df[col] = 0

        def calculate_flow_hash(row):
            m = hashlib.md5()
            hash_str = "".join(
                [
                    str(row.sip),
                    str(row.sport),
                    str(row.dip),
                    str(row.dport),
                    str(row.protocol),
                ]
            )
            m.update(hash_str.encode())
            return m.hexdigest()

        df["hash"] = [calculate_flow_hash(row) for _, row in df.iterrows()]
        return df
        
    def map(self, df_left: pd.DataFrame, df_right: pd.DataFrame,
            with_timestamp: bool = True) -> pd.DataFrame:
        """Map features between dataframes using flow hash"""
        df_left = self._add_hash_column(df_left)
        df_right = self._add_hash_column(df_right)
        keys = ["sip", "sport", "dip", "dport", "protocol", "first_timestamp_ms"]
        if not with_timestamp:
            keys = keys[:-1]
        # else:
        #     df_left['first_timestamp_ms'] = df_left['first_timestamp_ms'] // 1000  # convert first timestamp to ms

        df_left['id'] = df_left[keys].apply(lambda row: '_'.join(row.values.astype(str)), axis=1)
        df_right['id'] = df_right[keys].apply(lambda row: '_'.join(row.values.astype(str)), axis=1)
        df = df_left.merge(df_right, how='left', on='hash', suffixes=('', '_y'))
        df = df.drop([col for col in df.columns if col.endswith('_y')], axis=1)  # drop right key columns
        df = df.drop(columns=['id', 'hash'])  # drop id calculation columns
        return df

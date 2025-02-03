import hashlib


def add_hash_col(df):
    """
    Add a hash column to the dataframe
    """
    df = df.astype({'sport' : int, 'dport' : int, 'protocol': int})
    df  = df.copy()
    def calculate_flow_hash(row):
        m = hashlib.md5()
        hash = ''.join([str(row.sip), str(row.sport), str(row.dip), str(row.dport), str(row.protocol)#, str(row.first_timestamp)
                        ])
        m.update(hash.encode())
        return m.hexdigest()

    def populate_flow_hashes(df):
        hash= [calculate_flow_hash(row) for _, row in df.iterrows()]
        df['hash'] = hash
    populate_flow_hashes(df)
    return df
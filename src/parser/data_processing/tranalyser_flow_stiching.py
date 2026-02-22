"""Description:
Date: 2025-02-25
Author: TW

Tranalyser offers unidirectional flows. Each flow is represented by two directions—
'A' for the forward direction and 'B' for the backward direction, and they share the same flowInd.

- This script is used to stitch both the forward and backward flows together as a bidirectional flow
- In this script, first feature_bytes are converted to integers.
- The feature_keep_fwd values for forward flow are kept in the main record.
- The feature_keep_bwd values for backward flow are kept in the main record.
- The features_split are split into forward and backward features.

"""

import click
import os
import pandas as pd
from pathlib import Path
"""Data Files"""
data_path = [
    '/media/solana/Backup Plus/Data/dvc_data/2020a_Wireline_Ethernet/features',
    '/media/solana/Backup Plus/Data/dvc_data/2020c_Mobile_Wifi/features',
    '/media/solana/Backup Plus/Data/dvc_data/2021a_Wireline_Ethernet/features',
    '/media/solana/Backup Plus/Data/dvc_data/2021c_Mobile_LTE/features',
    '/media/solana/Backup Plus/Data/dvc_data/2022a_Wireline_Ethernet/features',
    '/media/solana/Backup Plus/Data/dvc_data/2023a_Wireline_Ethernet/features',
    '/media/solana/Backup Plus/Data/dvc_data/2023c_Mobile_LTE/features',
    '/media/solana/Backup Plus/Data/dvc_data/2023e_MacOS_Wifi/features',
    '/media/solana/Backup Plus/Data/dvc_data/2024ag_Wireline_Ethernet/features',
    '/media/solana/Backup Plus/Data/dvc_data/2024a_Wireline_Ethernet/features',
    '/media/solana/Backup Plus/Data/dvc_data/2024cg_Mobile_LTE/features',
    '/media/solana/Backup Plus/Data/dvc_data/2024c_Mobile_LTE/features',
    '/media/solana/Backup Plus/Data/dvc_data/2024e_MacOS_Wifi/features',
    '/media/solana/Backup Plus/Data/dvc_data/Homeoffice2024ag_Wireline_Ethernet/features',
    '/media/solana/Backup Plus/Data/dvc_data/Homeoffice2024a_Wireline_Ethernet/features',
    '/media/solana/Backup Plus/Data/dvc_data/Homeoffice2024c_Mobile_LTE/features',
    '/media/solana/Backup Plus/Data/dvc_data/Homeoffice2024e_MacOS_WiFi/features',
    '/media/solana/Backup Plus/Data/dvc_data/Homeoffice2025cg_Mobile_LTE/features',
    '/media/solana/Backup Plus/Data/dvc_data/Test2023a_Wireline_Ethernet/features',
    '/media/solana/Backup Plus/Data/dvc_data/Test2023c_Mobile_LTE/features',
    '/media/solana/Backup Plus/Data/dvc_data/Test2023e_MacOS_Wifi/features',
    '/media/solana/Backup Plus/Data/dvc_data/Test2024ag_Wireline_Ethernet/features',
    '/media/solana/Backup Plus/Data/dvc_data/Test2024a_Wireline_Ethernet/features',
    '/media/solana/Backup Plus/Data/dvc_data/Test2024cg_Mobile_LTE/features',
    '/media/solana/Backup Plus/Data/dvc_data/Test2024c_Mobile_LTE/features',
    '/media/solana/Backup Plus/Data/dvc_data/Test2024e_MacOS_Wifi/features'   
    ]

"""Feature names"""
features_original = [
    "dstPortClassN", "dstPortClass", "nDPIclass",
    "srcIpContinent", "srcIpCountry", "srcIpCity", "srcIpPostcode", "srcIpAccuracy",
    "srcIpLat", "srcIpLong", "srcIpTimeZone", "dstIpContinent", "dstIpCountry",
    "dstIpCity", "dstIpPostcode", "dstIpAccuracy", "dstIpLat", "dstIpLong", "dstIpTimeZone",
    "geoStat", "tp0fStat", "tp0fDis", "tp0fClName", "tp0fPrName", "tp0fVerName",
    "pktsSnt", "pktsRcvd", "padBytesSnt", "l7BytesSnt", "l7BytesRcvd", "minL7PktSz",
    "maxL7PktSz", "avgL7PktSz", "stdL7PktSz", "minIAT", "maxIAT", "avgIAT", "stdIAT",
    "pktps", "bytps", "pktAsm", "bytAsm", "tcpFStat", "ipMindIPID", "ipMaxdIPID",
    "ipMinTTL", "ipMaxTTL", "ipTTLChg", "ipToS", "ipFlags", "ipOptCnt", "ipOptCpCl_Num",
    "ip6OptCntHH_D", "ip6OptHH_D", "tcpISeqN", "tcpPSeqCnt", "tcpSeqSntBytes",
    "tcpSeqFaultCnt", "tcpPAckCnt", "tcpFlwLssAckRcvdBytes", "tcpAckFaultCnt",
    "tcpBFlgtMx", "tcpInitWinSz", "tcpAvgWinSz", "tcpMinWinSz", "tcpMaxWinSz",
    "tcpWinSzDwnCnt", "tcpWinSzUpCnt", "tcpWinSzChgDirCnt", "tcpWinSzThRt", "tcpFlags",
    "tcpAnomaly", "tcpJA4T", "tcpOptPktCnt", "tcpOptCnt", "tcpOptions", "tcpMSS",
    "tcpWS", "tcpMPTBF", "tcpMPF", "tcpMPAID", "tcpMPDSSF", "tcpTmS", "tcpTmER",
    "tcpEcI", "tcpUtm", "tcpBtm", "tcpSSASAATrip", "tcpRTTAckTripMin",
    "tcpRTTAckTripMax", "tcpRTTAckTripAvg", "tcpRTTAckTripJitAvg", "tcpRTTSseqAA",
    "tcpRTTAckJitAvg", "tcpStatesAFlags", "icmpStat", "icmpTCcnt",
    "icmpBFTypH_TypL_Code", "icmpTmGtw", "icmpEchoSuccRatio", "icmpPFindex",
    "dnsStat", "dnsHdrOPField", "dnsHFlg_OpC_RetC", "dnsCntQu_Asw_Aux_Add",
    "dnsAAAqF", "dnsQname", "dnsAname", "dnsAPname", "dns4Aaddress", "dns6Aaddress",
    "dnsQType", "dnsQClass", "dnsAType", "dnsAClass", "dnsATTL", "dnsMXpref",
    "dnsSRVprio", "dnsSRVwgt", "dnsSRVprt", "dnsOptStat", "natStat", "natErr",
    "natMCReq_Ind_Succ_Err", "natAddr_Port", "natXAddr_Port", "natPeerAddr_Port",
    "natOrigAddr_Port", "natRelayAddr_Port", "natDstAddr_Port", "natOtherAddr_Port",
    "natLifetime", "natUser", "natPass", "natRealm", "natSoftware", "natPMPReqEA_MU_MT",
    "natPMPRespEA_MU_MT", "natPMPSSSOE", "tftpStat", "tftpPFlow", "tftpNumOpcode",
    "tftpOpcode", "tftpNumParam", "tftpParam", "tftpNumErr", "tftpErrC", "ftpStat",
    "ftpCDFindex", "ftpCC", "ftpRC", "ftpNumUser", "ftpUser", "ftpNumPass", "ftpPass",
    "ftpNumCP", "ftpCP", "ftpPLen", "smtpStat", "smtpCC", "smtpRC", "smtpUsr",
    "smtpPW", "smtpSANum", "smtpESANum", "smtpERANum", "smtpSA", "smtpESA", "smtpERA",
    "httpStat", "httpAFlags", "httpMethods", "httpHeadMimes", "httpCFlags",
    "httpGet_Post", "httpRSCnt", "httpRSCode", "httpURL_Via_Loc_Srv_Pwr_UAg_XFr_Ref_Cky_Mim",
    "httpImg_Vid_Aud_Msg_Txt_App_Unk", "httpHosts", "httpURL", "httpMimes", "httpCookies",
    "httpImages", "httpVideos", "httpAudios", "httpMsgs", "httpAppl", "httpText",
    "httpPunk", "httpBdyURL", "httpUsrAg", "httpXFor", "httpRefrr", "httpVia",
    "httpLoc", "httpServ", "httpPwr", "gquicStat", "gquicPubFlags", "gquicFrameTypes",
    "gquicCID", "gquicSNI", "gquicUAID", "quicStat", "quicVersion", "quicFlags",
    "quicPktTypes", "quicDCID", "quicSCID", "quicODCID", "sslStat", "sslProto",
    "sslFlags", "sslVersion", "sslNumRecVer", "sslRecVer", "sslNumHandVer", "sslHandVer",
    "sslVuln", "sslAlert", "sslCipher", "sslNumExt", "sslExtList", "sslNumSuppVer",
    "sslSuppVer", "sslNumSigAlg", "sslSigAlg", "sslNumECPt", "sslECPt", "sslNumECFormats",
    "sslECFormats", "sslNumALPN", "sslALPNList", "sslNumALPS", "sslALPSList", "sslNumNPN",
    "sslNPNList", "sslNumCipher", "sslCipherList", "sslNumCC_A_H_AD_HB", "sslSessIdLen",
    "sslGMTTime", "sslServerName", "sslCertVersion", "sslCertSerial", "sslCertSha1FP",
    "sslCNotValidBefore_after_lifetime", "sslCSigAlg", "sslCKeyAlg", "sslCPKeyType_Size",
    "sslCSubjectCommonName", "sslCSubjectOrgName", "sslCSubjectOrgUnit", "sslCSubjectLocality",
    "sslCSubjectState", "sslCSubjectCountry", "sslCIssuerCommonName", "sslCIssuerOrgName",
    "sslCIssuerOrgUnit", "sslCIssuerLocality", "sslCIssuerState", "sslCIssuerCountry",
    "sslJA3Hash", "sslJA3Desc", "sslJA4", "sslJA4Desc", "voipStat", "voipType",
    "voipSSRC", "voipCSRC", "voipSRCnt", "rtpPMCnt", "rtpPMr", "sipMethods", "sipStatCnt",
    "sipReqCnt", "sipUsrAgnt", "sipRealIP", "sipFrom", "sipTo", "sipCallID", "sipContact",
    "sipStat", "sipReq", "sdpSessID", "sdpRFAdd", "sdpRAFPrt", "sdpRVFPrt", "sdpRTPMap",
    "voipFindex", "rtcpTPCnt", "rtcpTBCnt", "rtcpFracLst", "rtcpCPMCnt", "rtcpMaxIAT",
    "connSip", "connDip", "connSipDip", "connSipDprt", "connF", "connG", "connNumPCnt",
    "connNumBCnt", "tgStat", "nFpCnt", "L2L3L4Pl_Iat", "tCnt", "Ps_Iat_Cnt_PsCnt_IatCnt",
    "dsMinPl", "dsMaxPl", "dsMeanPl", "dsLowQuartilePl", "dsMedianPl", "dsUppQuartilePl",
    "dsIqdPl", "dsModePl", "dsRangePl", "dsStdPl", "dsRobStdPl", "dsSkewPl", "dsExcPl",
    "dsMinIat", "dsMaxIat", "dsMeanIat", "dsLowQuartileIat", "dsMedianIat", "dsUppQuartileIat",
    "dsIqdIat", "dsModeIat", "dsRangeIat", "dsStdIat", "dsRobStdIat", "dsSkewIat",
    "dsExcIat", "PyldEntropy", "PyldChRatio", "PyldBinRatio", "waveNumPnts", "waveNumLvl",
    "waveCoefDetailDB3", "waveCoefApprox3", "p0fSSLRule", "p0fSSLOS", "p0fSSLOS2",
    "p0fSSLBrowser", "p0fSSLComment"
]

feature_bytes = [
    "ipFlags", "tcpFlags", "tcpAnomaly", "tcpOptions", "tcpMPTBF", "tcpMPF", "tcpMPAID", "tcpMPDSSF", 
    "dnsStat", "dnsHdrOPField", 
    "gquicStat", "gquicPubFlags", "gquicFrameTypes","gquicCID", "gquicSNI", "gquicUAID", 
    "quicStat", "quicVersion", "quicFlags", "quicPktTypes", "quicDCID", "quicSCID", "quicODCID", 
    "sslStat", "sslProto", "sslFlags", "sslVersion","sslRecVer", "sslNumHandVer", "sslHandVer",
    "sslVuln", "sslAlert","sslCipher","sslECFormats"
]

feature_keep_fwd = [
    "dstPortClass", "nDPIclass", "sslServerName", "data_source", "fnName", "application_type", 
    "traffic_type", "pktsSnt", "pktsRcvd", "l7BytesSnt", "l7BytesRcvd", "connSip", "connDip",
    "tcpOptions", "tcpMPTBF", "tcpMPF", "tcpMPAID", "tcpMPDSSF",
    "dnsStat", "gquicStat", "gquicPubFlags", "gquicFrameTypes",
    "gquicCID", "gquicSNI", "gquicUAID", "quicStat", "quicVersion", "quicFlags",
    "quicPktTypes", "quicDCID", "quicSCID", "quicODCID","sslProto","sslVersion","sslRecVer",
    "sslVuln", "sslAlert"
]

feature_keep_bwd = [
    "dnsAAAqF", "dnsQname", "dnsAname", "dnsAPname", "dns4Aaddress", "dns6Aaddress"
]

features_split = [
    "srcIPOrg", "ipFlags","tcpFlags", "tcpAnomaly", "sslStat", "sslFlags","sslCipher","sslECFormats",
    "sslNumHandVer", "sslHandVer", "dnsHdrOPField", "firstTimeStamp", "lastTimeStamp", "duration",
    "minL7PktSz", "maxL7PktSz", "avgL7PktSz", "stdL7PktSz", "minIAT", "maxIAT", "avgIAT", "stdIAT",
    "pktps", "bytps", "pktAsm", "bytAsm", "ipMindIPID", "ipMaxdIPID", "ipMinTTL", "ipMaxTTL",
    "tp0fDis", "tcpISeqN", "tcpPSeqCnt", "tcpSeqSntBytes", "tcpSeqFaultCnt", "tcpPAckCnt",
    "tcpFlwLssAckRcvdBytes", "tcpAckFaultCnt", "tcpBFlgtMx", "tcpInitWinSz", "tcpAvgWinSz",
    "tcpMinWinSz", "tcpMaxWinSz", "tcpWinSzDwnCnt", "tcpWinSzUpCnt", "tcpWinSzChgDirCnt",
    "tcpWinSzThRt", "tcpWS", "tcpOptPktCnt", "tcpOptCnt", "tcpMSS", "tcpWS",
    "tcpEcI", "tcpUtm", "tcpBtm", "tcpSSASAATrip", "tcpRTTAckTripMin", "tcpRTTAckTripMax",
    "tcpRTTAckTripAvg", "tcpRTTAckTripJitAvg", "tcpRTTSseqAA", "tcpRTTAckJitAvg",
    "sslNumRecVer", "sslNumExt", "sslNumSuppVer", "sslSuppVer", "sslNumSigAlg", "sslSigAlg",
    "sslNumECPt", "sslECPt", "sslNumECFormats", "sslECFormats", "sslNumALPN", "sslNumALPS",
    "sslNumNPN", "sslNumCipher", "sslCipherList", "sslSessIdLen", "sslGMTTime", "sslServerName",
    "sslCertVersion", "sslCertSerial", "sslCertSha1FP", "sslCNotValidBefore_after_lifetime",
    "sslCSigAlg", "sslCKeyAlg", "sslCPKeyType_Size", "sslCSubjectCommonName", "sslCSubjectOrgName",
    "sslCSubjectOrgUnit", "sslCSubjectLocality", "sslCSubjectState", "sslCSubjectCountry",
    "sslCIssuerCommonName", "sslCIssuerOrgName", "sslCIssuerOrgUnit", "sslCIssuerLocality",
    "sslCIssuerState", "sslCIssuerCountry", "sslJA3Hash", "sslJA3Desc", "sslJA4", "sslJA4Desc",
    "connSipDip", "connSipDprt", "connF", "connG", "connNumPCnt", "connNumBCnt", "dsMinPl",
    "dsMaxPl", "dsMeanPl", "dsLowQuartilePl", "dsMedianPl", "dsUppQuartilePl", "dsIqdPl",
    "dsModePl", "dsRangePl", "dsStdPl", "dsRobStdPl", "dsSkewPl", "dsExcPl", "dsMinIat",
    "dsMaxIat", "dsMeanIat", "dsLowQuartileIat", "dsMedianIat", "dsUppQuartileIat",
    "dsIqdIat", "dsModeIat", "dsRangeIat", "dsStdIat", "dsRobStdIat", "dsSkewIat",
    "dsExcIat", "PyldEntropy", "PyldChRatio", "PyldBinRatio", "waveNumPnts", "waveNumLvl"
]

features_multivalue = ["tcpJA4T", "dnsHFlg_OpC_RetC","dnsCntQu_Asw_Aux_Add","dnsQType", "dnsQClass", "dnsAType", "dnsAClass", "dnsATTL", "dnsMXpref",
    "dnsSRVprio", "dnsSRVwgt", "dnsSRVprt", "dnsOptStat","sslExtList", "sslSigAlg", "sslECPt","sslALPNList","sslALPSList","sslNPNList","sslCipherList","sslNumCC_A_H_AD_HB"
    ]
def hex_to_int(val):
    """
    Convert a string like '0x0303' to its integer representation.
    If val is not a hex string or conversion fails, return val as-is.
    If there's a semicolon-delimited value, only take the first part.
    """
    if isinstance(val, str) and ";" in val:
        val = val.split(";")[0]
    if isinstance(val, str) and val.startswith("0x"):
        try:
            return int(val, 16)
        except ValueError:
            pass
    return val

def stitch_flows(group):
    """
    Given a group of flows with the same flowInd, stitch forward (dir 'A') and 
    backward (dir 'B') flows together, including renaming associated features.
    """
    try:
        bidir_flow = {'flowInd': group.name}
            
        # Separate forward and backward flows
        forward = group[group['%dir'] == 'A']
        backward = group[group['%dir'] == 'B']
        
        # Process forward flow if available
        if not forward.empty:
            f = forward.iloc[0]
            # Basic five-tuple from forward
            bidir_flow['srcIP']   = f['srcIP']
            bidir_flow['srcPort'] = f['srcPort']
            bidir_flow['dstIP']   = f['dstIP']
            bidir_flow['dstPort'] = f['dstPort']
            bidir_flow['l4Proto'] = f['l4Proto']
            
            # For features in features_split, store them as <feature>_fwd
            for feat in features_split:
                bidir_flow[f"{feat}_fwd"] = f.get(feat, None)
            
            # For features in feature_keep_fwd, keep them in the main record (no _fwd suffix)
            for feat in feature_keep_fwd:
                bidir_flow[feat] = f.get(feat, None)
        else:
            # No forward flow: set everything to None
            bidir_flow['srcIP']   = None
            bidir_flow['srcPort'] = None
            bidir_flow['dstIP']   = None
            bidir_flow['dstPort'] = None
            bidir_flow['l4Proto'] = None
            for feat in features_split:
                bidir_flow[f"{feat}_fwd"] = None
            for feat in feature_keep_fwd:
                bidir_flow[feat] = None

        # Process backward flow if available
        if not backward.empty:
            b = backward.iloc[0]
            # For features in features_split, store them as <feature>_bwd
            for feat in features_split:
                bidir_flow[f"{feat}_bwd"] = b.get(feat, None)
            
            # For features in feature_keep_bwd, keep them in the main record (no _bwd suffix)
            for feat in feature_keep_bwd:
                bidir_flow[feat] = b.get(feat, None)
        else:
            for feat in features_split:
                bidir_flow[f"{feat}_bwd"] = None
            for feat in feature_keep_bwd:
                bidir_flow[feat] = None

        # If no forward flow exists but a backward flow does, reverse the five-tuple from backward
        if forward.empty and not backward.empty:
            bidir_flow['srcIP']   = b['dstIP']
            bidir_flow['srcPort'] = b['dstPort']
            bidir_flow['dstIP']   = b['srcIP']
            bidir_flow['dstPort'] = b['srcPort']
            bidir_flow['l4Proto'] = b['l4Proto']
            
        return pd.Series(bidir_flow)
    except Exception as e:
        print(f"Error in stitch_flows: {e}")
        return None

@click.group()
def cli():
    """CLI tool for converting and stitching Tranalyser flows."""
    pass

@cli.command()
@click.argument('input_csv',  type=click.Path(exists=True))
@click.option('--output_csv', required=False, type=click.Path(), help="Path to the output CSV file for the stitched flows.")
def process(input_csv):
    
    failed_files = []
    for input_file_path in data_path: 
        # Get the relative path structure after 'pcaps' directory
        features_path = Path(input_file_path)           
        files = list(features_path.glob('**/*.csv'))
        total_files = len(files)
        for i, file in enumerate(files):
            print(f'[{i}/{total_files}] -> {file} ')
            head, tail = os.path.split(file)
            head = head.replace('features', 'tranalyzer_bidirectional_features')
            if not os.path.exists(head):
                os.makedirs(head)
            # tail = tail.replace('.csv', '.csv')
            features_file_path = Path(head, tail)

            # 1. Load the CSV file containing unidirectional flows
            df = pd.read_csv(input_csv)
            
            # 2. Convert hex/byte notation to integers where applicable
            existing_byte_cols = [col for col in feature_bytes if col in df.columns]
            df[existing_byte_cols] = df[existing_byte_cols].applymap(hex_to_int)
            
        
            
            # 3. Group by the unique flow identifier (flowInd) and stitch flows together
            bidirectional_df = df.groupby('flowInd').apply(stitch_flows).reset_index(drop=True)
            
            # 4. Reorder the columns in the final output:
            #    Basic five-tuple fields first
            basic_cols = ['flowInd', 'srcIP', 'srcPort', 'dstIP', 'dstPort', 'l4Proto']
            
            #    For each feature in features_split, place forward and backward columns together
            feature_cols = []
            for feat in features_split:
                feature_cols.append(f"{feat}_fwd")
                feature_cols.append(f"{feat}_bwd")
            
            #    Then the "keep_fwd" and "keep_bwd" features
            final_cols = basic_cols + feature_cols + feature_keep_fwd + feature_keep_bwd
            
            # 5. Filter out columns that might not exist (to avoid KeyError if a column is missing)
            existing_final_cols = [col for col in final_cols if col in bidirectional_df.columns]
            bidirectional_df = bidirectional_df[existing_final_cols]
            
            # 6. Save the reordered bidirectional flows to the output CSV file
            bidirectional_df.to_csv(features_file_path, index=False)
            
            # 7. Print the resulting DataFrame for inspection
            print(bidirectional_df)

if __name__ == '__main__':
    cli()

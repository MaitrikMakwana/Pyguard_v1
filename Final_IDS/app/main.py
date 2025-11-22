"""
Main Flask Application for PCAP Attack Detection Microservice
"""

import os
import tempfile
import traceback
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

try:
    from config.config import Config
    from app.services.cicflowmeter_service import run_cicflowmeter
    from app.services.feature_alignment_service import align_csv_features
    from app.services.prediction_service import predict_attacks_from_csv
except ImportError:
    from Final_IDS.config.config import Config  # type: ignore
    from Final_IDS.app.services.cicflowmeter_service import run_cicflowmeter  # type: ignore
    from Final_IDS.app.services.feature_alignment_service import align_csv_features  # type: ignore
    from Final_IDS.app.services.prediction_service import predict_attacks_from_csv  # type: ignore


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = Config.MAX_CONTENT_LENGTH
app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()


def process_pcap_to_attacks(pcap_file_path):
    """
    Complete pipeline: PCAP -> CSV -> Aligned CSV -> Predictions
    
    Args:
        pcap_file_path: Path to input pcap file
    
    Returns:
        Dictionary with attack detection results
    """
    import shutil
    temp_dir = tempfile.mkdtemp()
    
    try:
        import pandas as pd
        
        # Step 1: Convert PCAP to CSV using CICFlowMeter
        print("Step 1: Converting PCAP to CSV using CICFlowMeter...")
        cic_csv_path = run_cicflowmeter(pcap_file_path, temp_dir)
        
        # Preserve metadata columns before alignment (IP addresses, Flow ID, etc.)
        print("Preserving metadata columns...")
        original_df = pd.read_csv(cic_csv_path)
        
        # Find IP address columns (case-insensitive, handle various formats)
        src_ip_col = None
        dst_ip_col = None
        flow_id_col = None
        
        for col in original_df.columns:
            col_lower = col.lower().replace('_', ' ').replace('-', ' ')
            if src_ip_col is None and ('src ip' in col_lower or 'source ip' in col_lower):
                src_ip_col = col
            if dst_ip_col is None and ('dst ip' in col_lower or 'destination ip' in col_lower or 'dest ip' in col_lower):
                dst_ip_col = col
            if flow_id_col is None and 'flow id' in col_lower:
                flow_id_col = col
        
        # Also check for exact lowercase matches (Python cicflowmeter format)
        if src_ip_col is None and 'src_ip' in original_df.columns:
            src_ip_col = 'src_ip'
        if dst_ip_col is None and 'dst_ip' in original_df.columns:
            dst_ip_col = 'dst_ip'
        
        # Create metadata dataframe with found columns
        metadata_cols = []
        if flow_id_col:
            metadata_cols.append(flow_id_col)
        if src_ip_col:
            metadata_cols.append(src_ip_col)
        if dst_ip_col:
            metadata_cols.append(dst_ip_col)
        
        metadata_df = original_df[metadata_cols].copy() if metadata_cols else pd.DataFrame()
        print(f"Preserved {len(metadata_cols)} metadata columns: {metadata_cols}")
        
        # Step 2: Align CSV features to match model schema
        print("Step 2: Aligning CSV features...")
        aligned_csv_path = os.path.join(temp_dir, "aligned_features.csv")
        align_csv_features(cic_csv_path, aligned_csv_path)
        
        # Step 3: Run prediction
        print("Step 3: Running attack detection...")
        results_df = predict_attacks_from_csv(aligned_csv_path)
        
        # Step 4: Merge metadata back into results
        if not metadata_df.empty and len(metadata_df) == len(results_df):
            # Reset indices to ensure alignment
            metadata_df = metadata_df.reset_index(drop=True)
            results_df = results_df.reset_index(drop=True)
            
            # Add metadata columns to results
            if flow_id_col and flow_id_col in metadata_df.columns:
                results_df['flow_id'] = metadata_df[flow_id_col].values
            if src_ip_col and src_ip_col in metadata_df.columns:
                results_df['src_ip'] = metadata_df[src_ip_col].values
            if dst_ip_col and dst_ip_col in metadata_df.columns:
                results_df['dst_ip'] = metadata_df[dst_ip_col].values
        
        # Step 5: Aggregate results
        attack_summary = results_df['Predicted_Label'].value_counts().to_dict()
        total_flows = len(results_df)
        
        # Calculate statistics
        avg_confidence = results_df['Confidence'].mean()
        attack_flows = results_df[results_df['Predicted_Label'] != 'BENIGN']
        num_attacks = len(attack_flows)
        
        # Get top attacks
        top_attacks = []
        for label, count in attack_summary.items():
            label_df = results_df[results_df['Predicted_Label'] == label]
            avg_conf = label_df['Confidence'].mean()
            top_attacks.append({
                'attack_type': label,
                'count': int(count),
                'percentage': round((count / total_flows) * 100, 2),
                'avg_confidence': round(float(avg_conf), 4)
            })
        
        # Sort by count
        top_attacks.sort(key=lambda x: x['count'], reverse=True)
        
        # Prepare detailed results with proper field names
        detailed_results = []
        for idx, row in results_df.head(100).iterrows():
            # Get flow_id, src_ip, dst_ip with fallbacks
            flow_id = row.get('flow_id', idx + 1)
            if pd.isna(flow_id):
                flow_id = idx + 1
            
            src_ip = row.get('src_ip', 'N/A')
            if pd.isna(src_ip) or src_ip == '':
                src_ip = 'N/A'
            
            dst_ip = row.get('dst_ip', 'N/A')
            if pd.isna(dst_ip) or dst_ip == '':
                dst_ip = 'N/A'
            
            record = {
                'flow_id': int(flow_id) if isinstance(flow_id, (int, float)) else str(flow_id),
                'src_ip': str(src_ip),
                'dst_ip': str(dst_ip),
                'Predicted_Label': str(row.get('Predicted_Label', 'UNKNOWN')),
                'Confidence': float(row.get('Confidence', 0.0))
            }
            detailed_results.append(record)
        
        result = {
            'status': 'success',
            'total_flows': int(total_flows),
            'attack_flows': int(num_attacks),
            'benign_flows': int(total_flows - num_attacks),
            'average_confidence': round(float(avg_confidence), 4),
            'attack_summary': attack_summary,
            'top_attacks': top_attacks,
            'detailed_results': detailed_results
        }
        
        return result
        
    except Exception as e:
        print(f"Error in pipeline: {str(e)}")
        traceback.print_exc()
        return {
            'status': 'error',
            'error': str(e),
            'traceback': traceback.format_exc()
        }
    
    finally:
        # Cleanup temp directory
        try:
            shutil.rmtree(temp_dir)
        except:
            pass


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'PCAP Attack Detection Service'}), 200


@app.route('/analyze', methods=['POST'])
def analyze_pcap():
    """
    Main endpoint: Upload a pcap file and get attack detection results
    
    Returns JSON with attack detection results
    """
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.lower().endswith('.pcap'):
            return jsonify({'error': 'File must be a .pcap file'}), 400
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        pcap_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(pcap_path)
        
        print(f"Processing pcap file: {filename}")
        
        # Process the pcap file
        results = process_pcap_to_attacks(pcap_path)
        
        # Clean up uploaded file
        try:
            os.remove(pcap_path)
        except:
            pass
        
        if results['status'] == 'error':
            return jsonify(results), 500
        
        return jsonify(results), 200
        
    except Exception as e:
        print(f"Error in analyze endpoint: {str(e)}")
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


@app.route('/analyze_file', methods=['POST'])
def analyze_pcap_file_path():
    """
    Alternative endpoint: Provide path to existing pcap file
    
    Body: {"pcap_path": "/path/to/file.pcap"}
    """
    try:
        data = request.get_json()
        
        if not data or 'pcap_path' not in data:
            return jsonify({'error': 'pcap_path not provided'}), 400
        
        pcap_path = data['pcap_path']
        
        if not os.path.exists(pcap_path):
            return jsonify({'error': f'File not found: {pcap_path}'}), 404
        
        if not pcap_path.lower().endswith('.pcap'):
            return jsonify({'error': 'File must be a .pcap file'}), 400
        
        print(f"Processing pcap file: {pcap_path}")
        
        # Process the pcap file
        results = process_pcap_to_attacks(pcap_path)
        
        if results['status'] == 'error':
            return jsonify(results), 500
        
        return jsonify(results), 200
        
    except Exception as e:
        print(f"Error in analyze_file endpoint: {str(e)}")
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


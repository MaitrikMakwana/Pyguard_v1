import sys, os, traceback
sys.path.insert(0, 'd:/PyGuard-main')
os.chdir('d:/PyGuard-main')

try:
    from Final_IDS.app.services.cicflowmeter_service import run_cicflowmeter
    from Final_IDS.app.services.feature_alignment_service import align_csv_features
    from Final_IDS.app.models.gcn_model import load_model_and_preprocessors, preprocess_data, create_graph
    import pandas as pd, numpy as np, torch, tempfile

    pcap_path = 'd:/PyGuard-main/Final_IDS/innotech.pcap'
    tmp = tempfile.mkdtemp()

    print('Step 1: CICFlowMeter...')
    csv_path = run_cicflowmeter(pcap_path, tmp)

    print('Step 2: Align features...')
    aligned_path = os.path.join(tmp, 'aligned.csv')
    align_csv_features(csv_path, aligned_path)

    df_aligned = pd.read_csv(aligned_path)
    print('Aligned shape:', df_aligned.shape)

    # Check key features AFTER alignment
    print('Key feature values after alignment (should be NON-ZERO now):')
    for col in ['Flow Bytes/s', 'Flow Packets/s', 'Total Fwd Packets', 'SYN Flag Count', 'Flow Duration', 'Fwd IAT Total']:
        if col in df_aligned.columns:
            vals = df_aligned[col]
            print(f'  {col}: mean={vals.mean():.2f}  zeros%={(vals==0).mean()*100:.1f}%')
        else:
            print(f'  {col}: MISSING from aligned CSV!')

    print()
    print('Step 3: Model predictions...')
    model, scaler, label_encoder, metadata, device = load_model_and_preprocessors()

    df_pred = pd.read_csv(aligned_path)
    X_scaled = preprocess_data(df_pred, scaler, metadata['feature_columns'])
    data = create_graph(X_scaled, k=metadata['k_neighbors'])
    data = data.to(device)

    model.eval()
    with torch.no_grad():
        out = model(data.x, data.edge_index)
        predictions = out.argmax(dim=1).cpu().numpy()
        probabilities = torch.softmax(out, dim=1).cpu().numpy()

    predicted_labels = label_encoder.inverse_transform(predictions)
    confidence_scores = np.max(probabilities, axis=1)

    print('=== RESULTS (before confidence threshold) ===')
    print('Total flows:', len(predicted_labels))
    unique, counts = np.unique(predicted_labels, return_counts=True)
    for u, c in zip(unique, counts):
        avg_conf = float(np.mean(confidence_scores[predicted_labels == u]))
        pct = c / len(predicted_labels) * 100
        print(f'  {u}: {c} ({pct:.1f}%)  avg_conf={avg_conf:.3f}')

    print()
    print('Confidence distribution for non-BENIGN predictions:')
    for lbl in metadata['class_names']:
        if lbl == 'BENIGN':
            continue
        mask = predicted_labels == lbl
        if mask.any():
            confs = confidence_scores[mask]
            below75 = int((confs < 0.75).sum())
            above75 = int((confs >= 0.75).sum())
            print(f'  {lbl}: total={int(mask.sum())}  below_0.75={below75}  above_0.75={above75}  min={confs.min():.3f}  max={confs.max():.3f}')

    print()
    print('First 5 flows:')
    for i in range(min(5, len(predicted_labels))):
        probs_str = '  '.join([f'{cls}:{probabilities[i,j]:.3f}' for j, cls in enumerate(metadata['class_names'])])
        print(f'  Flow {i}: pred={predicted_labels[i]}  conf={confidence_scores[i]:.3f}  [{probs_str}]')

except Exception:
    traceback.print_exc()

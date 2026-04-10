from ai.train import generate_synthetic_data


def test_generate_synthetic_data_distribution():
    X, y = generate_synthetic_data(seed=42)
    assert X.shape == (2000, 16)
    assert y.shape == (2000,)
    counts = {cls: int((y == cls).sum()) for cls in range(5)}
    assert counts[0] == 400
    assert counts[1] == 600
    assert counts[2] == 500
    assert counts[3] == 300
    assert counts[4] == 200

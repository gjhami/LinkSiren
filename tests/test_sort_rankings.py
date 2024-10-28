from linksiren.pure_functions import sort_rankings


def test_empty():
    folder_rankings = {}
    expected_result = {}
    assert sort_rankings(folder_rankings) == expected_result


def test_none():
    folder_rankings = None
    expected_result = {}
    assert sort_rankings(folder_rankings) == expected_result


def test_single():
    folder_rankings = {"Folder1": 10}
    expected_result = {"Folder1": 10}
    assert sort_rankings(folder_rankings) == expected_result


def test_multiple_unique():
    folder_rankings = {"Folder1": 10, "Folder2": 5, "Folder3": 8}
    expected_result = {"Folder1": 10, "Folder3": 8, "Folder2": 5}
    assert sort_rankings(folder_rankings) == expected_result


def test_multiple_duplicate():
    folder_rankings = {"Folder1": 10, "Folder2": 5, "Folder3": 10}
    expected_result = {"Folder1": 10, "Folder3": 10, "Folder2": 5}
    assert sort_rankings(folder_rankings) == expected_result


def test_multiple_negatives():
    folder_rankings = {"Folder1": -10, "Folder2": -5, "Folder3": -8}
    expected_result = {"Folder2": -5, "Folder3": -8, "Folder1": -10}
    assert sort_rankings(folder_rankings) == expected_result

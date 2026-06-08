def calc_pos_score(change_line: int, vuln_line: int) -> float:
    dist = abs(change_line - vuln_line)
    if dist == 0: return 1.0
    if dist <= 2: return 0.8
    if dist <= 5: return 0.5
    if dist <= 10: return 0.2
    return 0.1

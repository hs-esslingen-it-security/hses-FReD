def print_progress_bar(tag, i, max, new_line = False):
    percentage = 100 * i / float(max)
    filledLength = int(percentage)
    bar = '█' * filledLength + '-' * (100 - filledLength)
    print(f'\r{tag} ({i}/{max}): |{bar}| {filledLength}%', end = '\r' if not new_line and i < max else '\n')
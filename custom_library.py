def load_yaml(path):
    import yaml
    with open(path, 'r') as file:
        data = yaml.safe_load(file)
    return data
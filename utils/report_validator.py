def validate_required_fields(data, required_fields):
    """
    Check whether required fields are present and not empty.
    """

    missing_fields = []

    for field in required_fields:
        value = data.get(field)

        if value is None or value == "" or value == [] or value == {}:
            missing_fields.append(field)

    return missing_fields

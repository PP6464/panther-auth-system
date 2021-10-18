RegExp alphanumeric = RegExp(r"^[a-zA-Z0-9]+$");
RegExp urlSafe = RegExp(r"^[a-zA-Z0-9-_@.]+$");
RegExp nameSafe = RegExp(r"^[a-zA-Z0-9-_@. ]+$");
bool checkEmpty(String? obj) => obj == null || obj.isEmpty;
function checkSuperuser(username) {
    if(username == "admin") {
        return true;
    }
    return false;
}

checkSuperuser(username);

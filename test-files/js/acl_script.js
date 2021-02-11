function checkAcl(username, topic, clientid, acc) {
    if(username != "correct") {
        return false;
    }

    if(topic != "test/topic") {
        return false;
    }

    if(clientid != "id") {
        return false;
    }

    if(acc != 1) {
        return false;
    }

    return true;
}

checkAcl(username, topic, clientid, acc);

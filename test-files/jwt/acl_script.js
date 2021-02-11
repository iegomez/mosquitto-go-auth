function checkAcl(token, topic, clientid, acc) {
    if(token != "correct") {
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

checkAcl(token, topic, clientid, acc);

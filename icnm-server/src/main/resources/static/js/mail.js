function view(id) {
    window.location.href = "/icnm/appInfo/view?id=" + id;
}

function del(id) {
    window.location.href = "/icnm/appInfo/del?id=" + id;
}

function cancel() {
    history.back();
}
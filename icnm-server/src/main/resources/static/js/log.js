function searchByPara() {
    var account = $("#account").val();
    window.location.href = "/icnm/log/list?account=" + escape(escape(account));
}

function view(id) {
    window.location.href = "/icnm/log/view?id=" + id;
}

function cancel() {
    history.back();
}

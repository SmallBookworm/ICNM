function searchByPara() {
    var account = $("#account").val();
    window.location.href = "/icnm/log/list?account=" + escape(escape(account));
}

function add() {
    window.location.href = "/icnm/appInfo/edit";
}


function view(id) {
    window.location.href = "/icnm/appInfo/view?id=" + id;
}

function edit(id) {
    window.location.href = "/icnm/appInfo/edit?id=" + id;
}

function del(id) {
    if (confirm('你确定要删除吗？')) {
        window.location.href = "/icnm/appInfo/del?id=" + id;
    }
}

function viewDate(id, dates) {
    window.location.href = "/icnm/appInfo/view?id=" + id + "&date=" + dates;
}

function cancel() {
    history.back();
}

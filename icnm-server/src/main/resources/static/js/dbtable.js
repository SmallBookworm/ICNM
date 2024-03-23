function view(id) {
    window.location.href = "/icnm/dbTable/edit?id=" + id;
}


function add() {
    window.location.href = "/icnm/dbTable/edit";
}

function del(id) {
    if (confirm('你确定要删除吗？')) {
        window.location.href = "/icnm/dbTable/del?id=" + id;
    }
}

function viewChart(id) {
    window.location.href = "/icnm/dbTable/viewChart?id=" + id;
}

function cancel() {
    history.back();
}

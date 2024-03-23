function view(id) {
    window.location.href = "/icnm/dbInfo/edit?id=" + id;
}


function add() {
    window.location.href = "/icnm/dbInfo/edit";
}

function del(id) {
    if (confirm('你确定要删除吗？同时也将删除数据源对应的数据表')) {
        window.location.href = "/icnm/dbInfo/del?id=" + id;
    }
}

function cancel() {
    history.back();
}

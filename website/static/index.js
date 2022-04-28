function deleteNote(noteId) {
  fetch("/delete-note", {
    method: "POST",
    body: JSON.stringify({ noteId: noteId }),
  }).then((_res) => {
    window.location.href = "/";
  });
}


// <-- Rename a task 
var renameTaskId; 

function renameFile() {
  var newname = document.getElementById("txt-content").value;
  id = renameTaskId;
  fetch("/rename/", {
    method: "POST",
    body: JSON.stringify({ id: id, newname: newname }),
  }).then((_res) => {
    window.location.href = "/upload/";
  });
}

function renameFileTaskId(id) {
  renameTaskId = id;
}
// Rename a task -->
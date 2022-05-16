

// <-- Rename a task 
let renameTaskId; 

function renameFile() {
  let newname = document.getElementById("txt-content").value;
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

$("textarea").keydown(function(e){
  // Enter pressed
  if (e.keyCode == 13)
  {
      //method to prevent from default behaviour
      e.preventDefault();
  }
});
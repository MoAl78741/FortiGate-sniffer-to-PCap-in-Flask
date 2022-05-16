

//rename task 
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


//banner
$("textarea").keydown(function(e){
  // Enter pressed
  if (e.keyCode == 13)
  {
      //method to prevent from default behaviour
      e.preventDefault();
  }
});

//dropzone
$(document).ready(function() {
  $("#input-b5").fileinput({showCaption: false, dropZoneEnabled: false});
});
function falert() {
    console.log('123');
    alert("yo");
}

async function saveFile() {
    let formData = new FormData();
    formData.append("file", fileupload.files[0]);
    await fetch('https://192.168.1.166:5000/', {method: "POST", body: formData});
    alert('File has been uploaded');
}
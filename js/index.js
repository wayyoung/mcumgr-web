document.addEventListener('DOMContentLoaded', async event => {

const screens = {
    initial: document.getElementById('initial-screen'),
    connecting: document.getElementById('connecting-screen'),
    connected: document.getElementById('connected-screen')
};
const uploadSlotId = document.getElementById('upload-slot-id');
const deviceName = document.getElementById('device-name');
const deviceNameInput = document.getElementById('device-name-input');
const connectButtonBluetooth = document.getElementById('button-connect-bluetooth');
const connectButtonSerial = document.getElementById('button-connect-serial');
const echoButton = document.getElementById('button-echo');
const disconnectButton = document.getElementById('button-disconnect');
const resetButton = document.getElementById('button-reset');
const imageStateButton = document.getElementById('button-image-state');
const eraseButton = document.getElementById('button-erase');
const testButton = document.getElementById('button-test');
const confirmButton = document.getElementById('button-confirm');
const imageList = document.getElementById('image-list');
const fileInfo = document.getElementById('file-info');
const fileStatus = document.getElementById('file-status');
const fileImage = document.getElementById('file-image');
const fileUpload = document.getElementById('file-upload');
const transportIsAvailable = document.getElementById('transport-is-available');
const transportIsAvailableMessage = document.getElementById('transport-is-available-message');
const connectBlockBluetooth = document.getElementById('connect-block-bluetooth');
const connectBlockSerial = document.getElementById('connect-block-serial');

let bluetoothAvailable = false
if (navigator && navigator.bluetooth) {
    bluetoothAvailable = await navigator.bluetooth.getAvailability();
}

let serialAvailable = false;
if (navigator && navigator.serial) {
    serialAvailable = true;
}

if (bluetoothAvailable && serialAvailable) {
    transportIsAvailableMessage.innerText = 'Bluetooth and serial are available in your browser.';
    transportIsAvailable.className = 'alert alert-success';
    connectBlockBluetooth.style.display = 'block';
    connectBlockSerial.style.display = 'block';
} else if (bluetoothAvailable ^ serialAvailable) {
    if (bluetoothAvailable) {
        transportIsAvailableMessage.innerText = `Bluetooth is available in your browser, but serial is not.`;
        connectBlockBluetooth.style.display = 'block';
    } else {
        transportIsAvailableMessage.innerText = `Serial is available in your browser, but Bluetooth is not.`;
        connectBlockSerial.style.display = 'block';
    }
    transportIsAvailable.className = 'alert alert-warning';
} else {
    transportIsAvailable.className = 'alert alert-danger';
    transportIsAvailableMessage.innerText = 'Neither Bluetooth nor serial are available in your browser.';
}

let file = null;
let fileData = null;
let images = [];

deviceNameInput.value = localStorage.getItem('deviceName');
deviceNameInput.addEventListener('change', () => {
    localStorage.setItem('deviceName', deviceNameInput.value);
});
const filters = [{ usbVendorId: 0x18d1, usbProductId: 0xffff }];
const mcumgr = new MCUManager();
mcumgr.onConnecting(() => {
    console.log('Connecting...');
    screens.initial.style.display = 'none';
    screens.connected.style.display = 'none';
    screens.connecting.style.display = 'block';
});

function _recovery_mode_connected() {
    deviceName.innerText = mcumgr.name;
    screens.connecting.style.display = 'none';
    screens.initial.style.display = 'none';
    screens.connected.style.display = 'block';
    imageList.innerHTML = '';
    mcumgr.cmdImageState();
}

mcumgr.onConnect(() => {
    mcumgr.cmdForceRecoveryMode();
});
var mgmt_start = 0;
mcumgr.onDisconnect(() => {
    deviceName.innerText = 'Connect your device';
    screens.connecting.style.display = 'none';
    screens.connected.style.display = 'none';
    screens.initial.style.display = 'block';
    mgmt_start = 0
});
mcumgr.onMessage(({ op, group, id, data, length }) => {
    switch (group) {
        case MGMT_GROUP_ID_OS:
            switch (id) {
                case OS_MGMT_ID_ECHO:
                    alert(data.r);
                    break;
                case OS_MGMT_ID_FORCE_RECOVERY_MODE:
                    if (mgmt_start == 0) {
                        mgmt_start = Date.now();
                    }
                    if (data.rc != 0 && (Date.now() - mgmt_start) <= 10000) {
                        console.log("not in recovery mode. rc: ", data.rc);
                        mcumgr.reconnect(filters); 
                    }else{
                        mgmt_start = 0;
                        _recovery_mode_connected();
                    }
                    break;
                case OS_MGMT_ID_TASKSTAT:
                    console.table(data.tasks);
                    break;
                case OS_MGMT_ID_MPSTAT:
                    console.log(data);
                    break;
            }
            break;
        case MGMT_GROUP_ID_IMAGE:
            switch (id) {
                case IMG_MGMT_ID_STATE:
                    images = data.images;
                    let imagesHTML = '';
                    if (images && images.length > 0) {
                        images.forEach(image => {
                            imagesHTML += `<div class="image ${image.active ? 'active' : 'standby'}">`;
                            imagesHTML += `<h2>Slot ${image.slot} ${image.active ? 'active' : 'standby'}</h2>`;
                            imagesHTML += '<table>';
                            imagesHTML += `<tr><th>Version</th><td>v${image.version}</td></tr>`;
                            if (image.label !== undefined) {
                                imagesHTML += `<tr><th>Label</th><td>${image.label}</td></tr>`;
                            }
                            if (image.bootable !== undefined) {
                                imagesHTML += `<tr><th>Bootable</th><td>${image.bootable}</td></tr>`;
                            }
                            if (image.confirmed !== undefined) {
                                imagesHTML += `<tr><th>Confirmed</th><td>${image.confirmed}</td></tr>`;
                            }
                            if (image.pending !== undefined) {
                                imagesHTML += `<tr><th>Pending</th><td>${image.pending}</td></tr>`;
                            }
                            if (image.hash !== undefined) {
                                const hashStr = Array.from(image.hash).map(byte => byte.toString(16).padStart(2, '0')).join('');
                                imagesHTML += `<tr><th>Hash</th><td>${hashStr}</td></tr>`;
                            }
                            imagesHTML += '</table>';
                            imagesHTML += '</div>';
                        });
                    } else {
                        imagesHTML = `<div class="alert alert-warning" role="alert">Device has no on-board firmware images</div>`
                    }
                    imageList.innerHTML = imagesHTML;

                    if (images) {
                        testButton.disabled = !(data.images.length > 1 && data.images[1].pending === false);
                        confirmButton.disabled = !(data.images.length > 0 && data.images[0].confirmed === false);
                    } else {
                        testButton.disabled = true;
                        confirmButton.disabled = true;
                    }
                    break;
            }
            break;
        default:
            console.log('Unknown group');
            break;
    }
});

mcumgr.onImageUploadProgress(({ percentage }) => {
    if (percentage < 0) 
    {
        fileStatus.innerText = `Error!! rc = ${percentage}`;
        return;
    }
    fileStatus.innerText = `Uploading... ${percentage}%`;
});

mcumgr.onImageUploadFinished(() => {
    fileStatus.innerText = 'Upload complete';
    fileInfo.innerHTML = '';
    fileImage.value = '';
    mcumgr.cmdImageState();
});

fileImage.addEventListener('change', () => {
    file = fileImage.files[0];
    fileData = null;
    const reader = new FileReader();
    reader.onload = async () => {
        fileData = reader.result;
        try {
            const info = await mcumgr.imageInfo(fileData);
            let table = `<table>`
            table += `<tr><th>Version</th><td>v${info.version}</td></tr>`;
            table += `<tr><th>Hash</th><td>${info.hash}</td></tr>`;
            table += `<tr><th>File Size</th><td>${fileData.byteLength} bytes</td></tr>`;
            table += `<tr><th>Size</th><td>${info.imageSize} bytes</td></tr>`;
            table += `</table>`;

            fileStatus.innerText = 'Ready to upload';
            fileInfo.innerHTML = table;
            fileUpload.disabled = false;
        } catch (e) {
            fileInfo.innerHTML = `ERROR: ${e.message}`;
        }
    };
    reader.readAsArrayBuffer(file);
});
fileUpload.addEventListener('click', event => {
    fileUpload.disabled = true;
    sid = Number(uploadSlotId.value);
    event.stopPropagation();
    if (file && fileData) {
        mcumgr.cmdUpload(fileData, sid);
    }
});

connectButtonBluetooth.addEventListener('click', async () => {
    let filters = null;
    if (deviceNameInput.value) {
        filters = [{ namePrefix: deviceNameInput.value }];
    };
    await mcumgr.connect("bluetooth", filters);
});

connectButtonSerial.addEventListener('click', async () => {
    await mcumgr.connect("serial", filters);
});

disconnectButton.addEventListener('click', async () => {
    await mcumgr.disconnect();
});

echoButton.addEventListener('click', async () => {
    const message = prompt('Enter a text message to send', 'Hello World!');
    await mcumgr.smpEcho(message);
});

resetButton.addEventListener('click', async () => {
    await mcumgr.cmdReset();
});

imageStateButton.addEventListener('click', async () => {
    await mcumgr.cmdImageState();
});

eraseButton.addEventListener('click', async () => {
    await mcumgr.cmdImageErase();
});

testButton.addEventListener('click', async () => {
    if (images.length > 1 && images[1].pending === false) {
        await mcumgr.cmdImageTest(images[1].hash);
    }
});

confirmButton.addEventListener('click', async () => {
    if (images.length > 0 && images[0].confirmed === false) {
        await mcumgr.cmdImageConfirm(images[0].hash);
    }
});

});

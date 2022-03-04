
// Opcodes
const MGMT_OP_READ = 0;
const MGMT_OP_READ_RSP = 1;
const MGMT_OP_WRITE = 2;
const MGMT_OP_WRITE_RSP = 3;

// Groups
const MGMT_GROUP_ID_OS = 0;
const MGMT_GROUP_ID_IMAGE = 1;
const MGMT_GROUP_ID_STAT = 2;
const MGMT_GROUP_ID_CONFIG = 3;
const MGMT_GROUP_ID_LOG = 4;
const MGMT_GROUP_ID_CRASH = 5;
const MGMT_GROUP_ID_SPLIT = 6;
const MGMT_GROUP_ID_RUN = 7;
const MGMT_GROUP_ID_FS = 8;
const MGMT_GROUP_ID_SHELL = 9;

// OS group
const OS_MGMT_ID_ECHO = 0;
const OS_MGMT_ID_CONS_ECHO_CTRL = 1;
const OS_MGMT_ID_TASKSTAT = 2;
const OS_MGMT_ID_MPSTAT = 3;
const OS_MGMT_ID_DATETIME_STR = 4;
const OS_MGMT_ID_RESET = 5;

// Image group
const IMG_MGMT_ID_STATE = 0;
const IMG_MGMT_ID_UPLOAD = 1;
const IMG_MGMT_ID_FILE = 2;
const IMG_MGMT_ID_CORELIST = 3;
const IMG_MGMT_ID_CORELOAD = 4;
const IMG_MGMT_ID_ERASE = 5;

class MCUTransport {
    constructor(di = {}) {
        this._logger = di.logger || { info: console.log, error: console.error };
        this._userRequestedDisconnect = false;
    }
    onConnecting(callback) {
        this._connectingCallback = callback;
        return this;
    }
    onConnect(callback) {
        this._connectCallback = callback;
        return this;
    }
    onDisconnect(callback) {
        this._disconnectCallback = callback;
        return this;
    }
    onRawMessage(callback) {
        this._rawMessageCallback = callback;
        return this;
    }
    async disconnect() {
        this._userRequestedDisconnect = true;
    }
    async _connected() {
        if (this._connectCallback) await this._connectCallback();
    }
    async _disconnected() {
        this._logger.info('Disconnected.');
        if (this._disconnectCallback) this._disconnectCallback();
        this._userRequestedDisconnect = false;
    }
    _connecting() {
        if (this._connectingCallback) this._connectingCallback();
    }
    _rawMessage(message) {
        if (this._rawMessageCallback) this._rawMessageCallback(message)
    }
}

class MCUTransportBluetooth extends MCUTransport {
    constructor(di = {}) {
        super(di)
        this.SERVICE_UUID = '8d53dc1d-1db7-4cd3-868b-8a527460aa84';
        this.CHARACTERISTIC_UUID = 'da2e7828-fbce-4e01-ae9e-261174997c48';
        this._device = null;
        this._service = null;
        this._characteristic = null;
        this._buffer = new Uint8Array();
    }
    async _requestDevice(filters) {
        const params = {
            acceptAllDevices: true,
            optionalServices: [this.SERVICE_UUID]
        };
        if (filters) {
            params.filters = filters;
            params.acceptAllDevices = false;
        }
        return navigator.bluetooth.requestDevice(params);
    }
    async connect(filters) {
        try {
            this._device = await this._requestDevice(filters);
            this._logger.info(`Connecting to device ${this.name}...`);
            this._device.addEventListener('gattserverdisconnected', async event => {
                this._logger.info(event);
                if (!this._userRequestedDisconnect) {
                    this._logger.info('Trying to reconnect');
                    this._connect(1000);
                } else {
                    this._disconnected();
                }
            });
            this._connect(0);
        } catch (error) {
            this._logger.error(error);
            await this._disconnected();
            return;
        }
    }
    _connect() {
        setTimeout(async () => {
            try {
                this._connecting();
                const server = await this._device.gatt.connect();
                this._logger.info(`Server connected.`);
                this._service = await server.getPrimaryService(this.SERVICE_UUID);
                this._logger.info(`Service connected.`);
                this._characteristic = await this._service.getCharacteristic(this.CHARACTERISTIC_UUID);
                this._characteristic.addEventListener('characteristicvaluechanged', this._notification.bind(this));
                await this._characteristic.startNotifications();
                await this._connected();
            } catch (error) {
                this._logger.error(error);
                await this._disconnected();
            }
        }, 1000);
    }
    async disconnect() {
        await super.disconnect();
        await this._device.gatt.disconnect();
    }
    async _disconnected() {
        super._disconnected()
        this._device = null;
        this._service = null;
        this._characteristic = null;
    }
    async sendMessage(data) {
        return await this._characteristic.writeValueWithoutResponse(data);
    }
    _notification(event) {
        // console.log('message received');
        const message = new Uint8Array(event.target.value.buffer);
        // console.log(message);
        // console.log('<'  + [...message].map(x => x.toString(16).padStart(2, '0')).join(' '));
        this._buffer = new Uint8Array([...this._buffer, ...message]);
        const messageLength = this._buffer[2] * 256 + this._buffer[3];
        if (this._buffer.length < messageLength + 8) return;
        this._rawMessage(this._buffer.slice(0, messageLength + 8));
        this._buffer = this._buffer.slice(messageLength + 8);
    }
    get name() {
        return this._device && this._device.name;
    }
}

/**
 * Transformer that expects Uint8Array chunks as input and outputs
 * Uint8Arrays of lines delimited by 0x0A (\n), including the
 * terminating newline.
 * 
 * The mcumgr spec says nothing about carriage returns (\r), but at
 * least one implementation terminates its lines with \n\r, so we
 * must be careful to properly trim all line endings.
 */
 class LineTransformer {
    constructor() {
        this._chunks = [];
        this._length = 0;
    }

    transform(chunk, controller) {
        // Handle lines ended by this chunk
        let index = chunk.indexOf(0x0A);
        let start = 0;
        while (index != -1) {
            // Complete a line using previously stored chunks and the
            // start of this chunk
            const lineBuffer = new Uint8Array(this._length + index + 1);
            let offset = 0;
            for (const storedChunk of this._chunks) {
                lineBuffer.set(storedChunk, offset);
                offset += storedChunk.length;
            }
            lineBuffer.set(chunk.subarray(start, index+1), offset)
            // Trim carriage returns at the beginning or end of the line
            let trimmedStart = 0;
            let trimmedEnd = lineBuffer.length;
            for (var i=0; i < lineBuffer.length; i++) {
                if (lineBuffer[i] == 0x0D) {
                    trimmedStart++;
                } else {
                    break;
                }
            }
            for (var i=lineBuffer.length - 1; i >= 0; i--) {
                if (lineBuffer[i] == 0x0D) {
                    trimmedEnd--;
                } else {
                    break;
                }
            }
            // Output the trimmed line for downstream processing
            if (trimmedStart != 0 || trimmedEnd != lineBuffer.length) {
                controller.enqueue(lineBuffer.slice(trimmedStart, trimmedEnd));
            } else {
                controller.enqueue(lineBuffer);
            }
            // Clear stored chunks and keep searching
            this._chunks = []
            this._length = 0

            // Continue searching this chunk for more lines
            start = index + 1
            index = chunk.indexOf(0x0A, start)
        }

        // Store any remaining bytes from the chunk for later lines
        if (start == 0) {
            // No newline in this chunk at all
            this._chunks.push(chunk)
            this._length += chunk.length
        } else if (start < chunk.length) {
            // At least one byte remaining after processing newlines
            this._chunks.push(chunk.slice(start))
            this._length += chunk.length - start
        }
    }
}

/**
 * Port of from Zephyr's crc16_itu_t()
 *
 * @param number seed - 16-bit CRC seed value 
 * @param Array data - array-like sequence of 8-bit data values
 * @returns Checksum of data using polynomial 0x1021
 */
function crc16ITUT(seed, data) {
    seed &= 0xFFFF;
    for (const byte of data) {
        seed = ((seed >> 8) | (seed << 8)) & 0xFFFF;
        seed ^= (byte & 0xFF);
        seed ^= (seed & 0xFF) >> 4;
        seed = seed ^ ((seed << 12) & 0xFFFF);
        seed ^= (seed & 0xFF) << 5;
    }
    return seed;
}

/**
 * Transformer that expects complete lines as Uint8Arrays as input,
 * extracts the lines that contain mcumgr frames, reassembles them
 * and outputs complete mcumgr packets
 */
class ConsoleDeframerTransformer {
    constructor() {
        this._frameBodies = [];
        this._numDecodedBytes = 0;
        this._numExpectedBytes = 0;
    }

    transform(chunk, controller) {
        if (chunk.length < 7) {
            // Need at least the frame header, base64-encoded body,
            // and newline
            return;
        }
        let newPacket = false;
        if (chunk[0] == 0x06 && chunk[1] == 0x09) {
            // Initial frame of a new packet
            if (this._numExpectedBytes != 0) {
                // console.log(`Discarding partial packet due to new start frame`);
            }
            // Discard any existing state
            this._frameBodies = [];
            this._numDecodedBytes = 0;
            this._numExpectedBytes = 0;
            newPacket = true;
        } else if (chunk[0] == 0x04 && chunk[1] == 0x14) {
            // Continuation frame of an existing packet
            if (this._numDecodedBytes == this._numExpectedBytes) {
                // We don't have the beginning of this packet
                // Discard continuation frames until we get a new packet
                // console.log(`Discarding continuation frame without start frame`);
                return;
            }
        } else {
            // Not an mcumgr frame
            // console.log(`Discarding unframed line`);
            return;
        }
        // Decode the frame body from base64
        const frameBodyBase64 = String.fromCharCode.apply(null, chunk.subarray(2, chunk.length - 1));
        const frameBodyString = atob(frameBodyBase64);
        const frameBody = new Uint8Array(frameBodyString.length);
        for (let i=0; i < frameBodyString.length; i++) {
            frameBody[i] = frameBodyString.charCodeAt(i);
        }
        if (newPacket) {
            const view = new DataView(frameBody.buffer);
            // Read the number of decoded bytes expected, excluding the
            // 16-bit length, but including the 16-bit CRC.
            const packetLength = view.getUint16(0, false);
            // Overall, we expect 2 bytes for the packet length plus the
            // self-reported packet length.
            this._numExpectedBytes = packetLength + 2;
            this._numDecodedBytes = frameBody.length;
            this._frameBodies.push(frameBody)
        } else {
            // Append the frame body for reassembly
            this._frameBodies.push(frameBody)
            this._numDecodedBytes += frameBody.length
        }
        // Check if we have enough data to reassemble the packet
        if (this._numDecodedBytes == this._numExpectedBytes) {
            // Merge all of the frame bodies together into the whole packet
            // plus the packet length header and CRC16 trailer
            const packetBuffer = new Uint8Array(this._numDecodedBytes);
            let offset = 0;
            for (const body of this._frameBodies) {
                packetBuffer.set(body, offset);
                offset += body.length;
            }
            const view = new DataView(packetBuffer.buffer);
            const embeddedCrc16 = view.getUint16(packetBuffer.length - 2, false);
            const packet = packetBuffer.subarray(2, packetBuffer.length - 2);
            const calculatedCrc16 = crc16ITUT(0x0000, packet)
            if (calculatedCrc16 != embeddedCrc16) {
                // TODO: log a warning or something
                // console.log(`CRC mismatch - expected ${embeddedCrc16}, got ${calculatedCrc16}`);
            } else {
                // Output the packet body
                controller.enqueue(packetBuffer.subarray(2, packetBuffer.length - 2))
            }
            // Reset state
            this._frameBodies = [];
            this._numDecodedBytes = 0;
            this._numExpectedBytes = 0;
        } else if (this._numDecodedBytes > this._numExpectedBytes) {
            // Got too many bytes; discard and start over
            // console.log(`Expected ${this._numExpectedBytes} bytes, but got ${this._numDecodedBytes}`);
            // TODO: log a warning or something
            this._frameBodies = [];
            this._numDecodedBytes = 0;
            this._numExpectedBytes = 0;
        }
    }
}

class MCUTransportSerial extends MCUTransport{
    constructor(di = {}) {
        super(di)
        this._port = null;
        this._maxFrameSize = 127;
        // Account for the bytes needed for the frame header and newline
        const maxBase64Len = this._maxFrameSize - 3;
        // Take into account the 4 output bytes / 3 input bytes base64 ratio 
        this._maxBodyBytesPerFrame = Math.floor(maxBase64Len / 4) * 3;
        // Keep track of whether we know the target's input line buffer state
        this._flushed = false;
    }

    async connect(filters) {
        try {
            this._port = await navigator.serial.requestPort(filters);
            this._logger.info(`Connecting to device ${this.name}...`);
            if (this._port) {
                this._port.addEventListener('disconnect', async event => {
                    this._logger.info(event);
                    if (!this._userRequestedDisconnect) {
                        this._logger.info('Trying to reconnect');
                        this._connect(1000);
                    } else {
                        this._disconnected();
                    }
                });
            }
            this._connect(0);
        } catch (error) {
            this._logger.error(error);
            await this._disconnected();
            return;
        }
    }
    _connect(timeout) {
        setTimeout(async () => {
            try {
                this._connecting();
                const options = {
                    baudRate: 115200
                };
                await this._port.open(options);
                this._logger.info(`Port opened.`);
                this._inputStream = new TransformStream(new LineTransformer())
                this._inputStreamClosed = this._port.readable.pipeTo(this._inputStream.writable);
                this._messageStream = new TransformStream(new ConsoleDeframerTransformer());
                this._messageStreamClosed = this._inputStream.readable.pipeTo(this._messageStream.writable);
                this._reader = this._messageStream.readable.getReader();
                this._readIncoming(this._reader)
                this._writer = this._port.writable.getWriter();
                await this._connected();
            } catch (error) {
                this._logger.error(error);
                await this._disconnected();
            }
        }, timeout);
    }
    async _disconnected() {
        super._disconnected()
        this._port = null;
        this._inputStream = null;
        this._inputStreamClosed = null;
        this._messageStream = null;
        this._messageStreamClosed = null;
        this._reader = null;
        this._writer = null;
        this._flushed = false;
    }
    async disconnect() {
        await super.disconnect();
        if (this._reader) {
            this._reader.cancel();
            await this._inputStreamClosed.catch(reason => {});
            await this._messageStreamClosed.catch(reason => {});
        }
        if (this._writer) {
            await this._writer.close();
        }
        if (this._port) {
            await this._port.close();
        }
        await this._disconnected();
    }
    get name() {
        return "Serial";
    }
    async sendMessage(data) {
        const packetLength = data.byteLength + 2;
        const calculatedCrc16 = crc16ITUT(0x0000, data);
        // Concatenate the length, packet, and CRC16 together
        const body = new Uint8Array(packetLength + 2);
        const view = new DataView(body.buffer)
        view.setUint16(0, packetLength, false);
        body.set(data, 2);
        view.setUint16(packetLength, calculatedCrc16, false);
        // Split into frames no larger than the maximum frame size
        const numFramesNeeded = Math.ceil(body.length / this._maxBodyBytesPerFrame);
        const frames = [];
        for (var i=0; i < numFramesNeeded; i++) {
            const offset = i * this._maxBodyBytesPerFrame;
            const bodyBytesRemaining = body.length - offset;
            const numBytesToEncode = Math.min(bodyBytesRemaining, this._maxBodyBytesPerFrame);
            const encodedString = btoa(String.fromCharCode.apply(null, body.subarray(offset, offset + numBytesToEncode)));
            const frame = new Uint8Array(3 + encodedString.length);
            if (i == 0) {
                // First frame is a packet start frame
                frame[0] = 0x06;
                frame[1] = 0x09;
                frame[frame.length - 1] = 0x0A;
            } else {
                // Subsequent frames are continuation frames
                frame[0] = 0x04;
                frame[1] = 0x14;
            }
            // Add the base64-encoded frame body
            for (var j=0; j < encodedString.length; j++) {
                frame[2+j] = encodedString.charCodeAt(j);
            }
            // Add the newline terminator
            frame[frame.length - 1] = 0x0A;
            // Add the frame to the list of frames to send
            frames.push(frame)
        }

        if (!this._flushed) {
            // Flush the target's line buffer if this is the first time
            // we're writing to it since opening the serial connection.
            await this._writer.write(new Uint8Array([0x0D, 0x0A]));
            this._flushed = true;
        }

        // Write each frame
        for (const frame of frames) {
            await this._writer.write(frame);
        }
    }
    async _readIncoming(reader) {
        while (true) {
            const {value, done} = await this._reader.read();
            if (value) {
                this._rawMessage(value);
            }
            if (done) {
                break;
            }
        }
    }
}

class MCUManager {
    constructor(di = {}) {
        this._mtu = 140;
        this._connectCallback = null;
        this._connectingCallback = null;
        this._disconnectCallback = null;
        this._messageCallback = null;
        this._imageUploadProgressCallback = null;
        this._uploadIsInProgress = false;
        
        this._logger = di.logger || { info: console.log, error: console.error };
        this._seq = 0;
        this._transport = null;
    }
    async connect(type, filters) {
        switch (type) {
            case 'bluetooth':
                this._transport = new MCUTransportBluetooth();
                break;
            case 'serial':
                this._transport = new MCUTransportSerial();
                break;
        }

        if (this._transport) {
            this._transport.onConnect(async () => await this._connected());
            this._transport.onDisconnect(() => this._disconnected());
            this._transport.onConnecting(() => this._connecting());
            this._transport.onRawMessage((message) => this._processMessage(message));
            await this._transport.connect(filters);
        }
    }
    disconnect() {
        if (this._transport) {
            return this._transport.disconnect();
        }
    }
    
    onConnecting(callback) {
        this._connectingCallback = callback;
        return this;
    }
    onConnect(callback) {
        this._connectCallback = callback;
        return this;
    }
    onDisconnect(callback) {
        this._disconnectCallback = callback;
        return this;
    }
    onMessage(callback) {
        this._messageCallback = callback;
        return this;
    }
    onImageUploadProgress(callback) {
        this._imageUploadProgressCallback = callback;
        return this;
    }
    onImageUploadFinished(callback) {
        this._imageUploadFinishedCallback = callback;
        return this;
    }
    async _connected() {
        if (this._connectCallback) this._connectCallback();
        if (this._uploadIsInProgress) {
            this._uploadNext();
        }
    }
    _disconnected() {
        if (this._disconnectCallback) this._disconnectCallback();
    }
    _connecting() {
        if (this._connectingCallback) this._connectingCallback();
    }
    
    get name() {
        return this._transport && this._transport.name;
    }
    async _sendMessage(op, group, id, data) {
        const _flags = 0;
        let encodedData = [];
        if (typeof data !== 'undefined') {
            encodedData = [...new Uint8Array(CBOR.encode(data))];
        }
        const length_lo = encodedData.length & 255;
        const length_hi = encodedData.length >> 8;
        const group_lo = group & 255;
        const group_hi = group >> 8;
        const message = [op, _flags, length_hi, length_lo, group_hi, group_lo, this._seq, id, ...encodedData];
        // console.log('>'  + message.map(x => x.toString(16).padStart(2, '0')).join(' '));
        await this._transport.sendMessage(Uint8Array.from(message));
        this._seq = (this._seq + 1) % 256;
    }
    _processMessage(message) {
        const [op, _flags, length_hi, length_lo, group_hi, group_lo, _seq, id] = message;
        const data = CBOR.decode(message.slice(8).buffer);
        const length = length_hi * 256 + length_lo;
        const group = group_hi * 256 + group_lo;
        if (group === MGMT_GROUP_ID_IMAGE && id === IMG_MGMT_ID_UPLOAD && data.rc === 0 && data.off) {
            this._uploadOffset = data.off;            
            this._uploadNext();
            return;
        }
        if (this._messageCallback) this._messageCallback({ op, group, id, data, length });
    }
    cmdReset() {
        return this._sendMessage(MGMT_OP_WRITE, MGMT_GROUP_ID_OS, OS_MGMT_ID_RESET);
    }
    smpEcho(message) {
        return this._sendMessage(MGMT_OP_WRITE, MGMT_GROUP_ID_OS, OS_MGMT_ID_ECHO, { d: message });
    }
    cmdImageState() {
        return this._sendMessage(MGMT_OP_READ, MGMT_GROUP_ID_IMAGE, IMG_MGMT_ID_STATE, {});
    }
    cmdImageErase() {
        return this._sendMessage(MGMT_OP_WRITE, MGMT_GROUP_ID_IMAGE, IMG_MGMT_ID_ERASE, {});
    }
    cmdImageTest(hash) {
        return this._sendMessage(MGMT_OP_WRITE, MGMT_GROUP_ID_IMAGE, IMG_MGMT_ID_STATE, { hash, confirm: false });
    }
    cmdImageConfirm(hash) {
        return this._sendMessage(MGMT_OP_WRITE, MGMT_GROUP_ID_IMAGE, IMG_MGMT_ID_STATE, { hash, confirm: true });
    }
    _hash(image) {
        return crypto.subtle.digest('SHA-256', image);
    }
    async _uploadNext() {
        if (this._uploadOffset >= this._uploadImage.byteLength) {
            this._uploadIsInProgress = false;
            this._imageUploadFinishedCallback();
            return;
        }

        const nmpOverhead = 8;
        const message = { data: new Uint8Array(), off: this._uploadOffset };
        if (this._uploadOffset === 0) {
            message.len = this._uploadImage.byteLength;
            message.sha = new Uint8Array(await this._hash(this._uploadImage));
        }
        this._imageUploadProgressCallback({ percentage: Math.floor(this._uploadOffset / this._uploadImage.byteLength * 100) });

        const length = this._mtu - CBOR.encode(message).byteLength - nmpOverhead;

        message.data = new Uint8Array(this._uploadImage.slice(this._uploadOffset, this._uploadOffset + length));

        this._uploadOffset += length;

        this._sendMessage(MGMT_OP_WRITE, MGMT_GROUP_ID_IMAGE, IMG_MGMT_ID_UPLOAD, message);
    }
    async cmdUpload(image, slot = 0) {
        if (this._uploadIsInProgress) {
            this._logger.error('Upload is already in progress.');
            return;
        }
        this._uploadIsInProgress = true;

        this._uploadOffset = 0;
        this._uploadImage = image;
        this._uploadSlot = slot;

        this._uploadNext();
    }
    async imageInfo(image) {
        // https://interrupt.memfault.com/blog/mcuboot-overview#mcuboot-image-binaries

        const info = {};
        const view = new DataView(image);

        // check header length
        if (view.byteLength < 32) {
            throw new Error('Invalid image (too short file)');
        }

        // check MAGIC bytes 0x96f3b83d
        if (view.getUint32(0, true) !== 0x96f3b83d) {
            throw new Error('Invalid image (wrong magic bytes)');
        }

        // check load address is 0x00000000
        if (view.getUint32(4, true) !== 0x00000000) {
            throw new Error('Invalid image (wrong load address)');
        }

        const headerSize = view[8] + view[9] * 2**8;

        // check protected TLV area size is 0
        if (view.getUint16(10, true)!== 0x0000) {
            throw new Error('Invalid image (wrong protected TLV area size)');
        }

        const imageSize = view.getUint32(12, true);
        info.imageSize = imageSize;

        // check image size is correct
        if (view.length < imageSize + headerSize) {
            throw new Error('Invalid image (wrong image size)');
        }


        const version = `${view.getUint8(20)}.${view.getUint8(21)}.${view.getUint16(22, true)}+${view.getUint32(24,true)}`;
        info.version = version;

        info.hash = [...new Uint8Array(await this._hash(image.slice(0, imageSize + 32)))].map(b => b.toString(16).padStart(2, '0')).join('');

        return info;
    }
}


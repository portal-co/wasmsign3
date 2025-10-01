"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.customSections = customSections;
exports.readLEB = readLEB;
function* customSections(array) {
    for (;;) {
        if (array.length === 0)
            return;
        const ga = array[0];
        let size;
        ({ value: size, array } = readLEB(array.subarray(1)));
        if (ga !== 0) {
            while (size !== 0n) {
                array = array.subarray(1);
                size--;
            }
            continue;
        }
        else {
            let nameSize;
            ({ value: nameSize, array } = readLEB(array));
            const nameBytes = array.subarray(0, Number(nameSize));
            array = array.subarray(Number(nameSize));
            const name = new TextDecoder().decode(nameBytes);
            yield { name, section: array.subarray(0, Number(size - nameSize)) };
            array = array.subarray(Number(size - nameSize));
        }
    }
}
function readLEB(array) {
    let value = 0n;
    for (let i = 0;; i++) {
        value |= BigInt(array[i] & 0x7f) << BigInt(i * 7);
        if (!(array[i] & 0x80))
            return { value, array: array.subarray(i + 1) };
    }
}

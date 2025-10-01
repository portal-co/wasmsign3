export function* customSections(a) {
    for (;;) {
        if (a.length === 0)
            return;
        const ga = a[0];
        let size;
        ({ value: size, array: a } = readLEB(a.subarray(1)));
        if (ga !== 0) {
            while (size !== 0n) {
                a = a.subarray(1);
                size--;
            }
            continue;
        }
        else {
            let nameSize;
            ({ value: nameSize, array: a } = readLEB(a));
            const nameBytes = a.subarray(0, Number(nameSize));
            a = a.subarray(Number(nameSize));
            const name = new TextDecoder().decode(nameBytes);
            yield { name, section: a.subarray(0, Number(size - nameSize)) };
            a = a.subarray(Number(size - nameSize));
        }
    }
}
export function readLEB(a) {
    let value = 0n;
    for (let i = 0;; i++) {
        value |= BigInt(a[i] & 0x7f) << BigInt(i * 7);
        if (a[i] & 0x80)
            return { value, array: a.subarray(i + 1) };
    }
}

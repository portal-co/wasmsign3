export declare function customSections(a: Uint8Array): Generator<{
    name: string;
    section: Uint8Array;
}, void, void>;
export declare function readLEB(a: Uint8Array): {
    value: bigint;
    array: Uint8Array;
};

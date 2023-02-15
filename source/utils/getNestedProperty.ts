export function getNestedProperty(obj: any, nestedKey: string): any {
    try {
        const keys = nestedKey.split('.');
        let value = obj;
        for (const key of keys) {
            value = value[key];
        }
        return value;
    } catch {
        return undefined;
    }
}

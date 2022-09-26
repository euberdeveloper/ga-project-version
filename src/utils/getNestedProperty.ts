export function getNestedProperty(obj: any, nestedKey: string): any {
    try {
        const keys = nestedKey.split('.');
        let value = obj;
        for (let i = 0; i < keys.length; i++) {
            value = value[keys[i]];
        }
        return value;
    }
    catch (error: any) {
        return undefined;
    }
}
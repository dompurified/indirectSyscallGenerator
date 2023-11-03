console.log('paste your entire INIT_SYSCALLS here\nafter you\'ve pasted, type end\n\n');
process.stdout.write('> ');
new Promise(resolve => {
    process.openStdin();
    const finalData = [];
    const handler = data => {
        data = data.toString().trim();
        if (data.toLowerCase() === 'end') {
            resolve(finalData);
            process.stdin.off('data', handler);
        } else {
            finalData.push(data);
            process.stdout.write('> ');
        }
    };
    process.stdin.on('data', handler);
}).then(input => {
    let names = input.join('\n').match(/i\(([^,]+)/g);
    if (!names) return;
    names = names.map(x => x.slice(2));

    console.log(names.map(name => `extern sysnum_Nt${name}: dword\nextern stub_Nt${name}: qword\n`).join('\n'));
    console.log('.code\n');
    console.log(names.map(name => `sys${name} proc\n\tmov eax, sysnum_Nt${name}\n\tmov r10, rcx\n\n\tjmp qword ptr [stub_Nt${name}]\nsys${name} endp`).join('\n\n'));
    console.log('\nend');
});
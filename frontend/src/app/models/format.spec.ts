import { formatBytes, sparkline } from './format';

describe('formatBytes', () => {
  it('should pick a readable unit, in French format', () => {
    expect(formatBytes(512)).toBe('512 o');
    expect(formatBytes(3072)).toBe('3,0 Ko');
    expect(formatBytes(64_800_000)).toBe('61,8 Mo');
    expect(formatBytes(1_610_612_736)).toBe('1,5 Go');
  });
});

describe('sparkline', () => {
  it('should scale each value against the maximum', () => {
    expect(sparkline([0, 50, 100])).toBe('▁▅█');
  });

  it('should stay flat without traffic', () => {
    expect(sparkline([0, 0])).toBe('▁▁');
    expect(sparkline([])).toBe('');
  });
});

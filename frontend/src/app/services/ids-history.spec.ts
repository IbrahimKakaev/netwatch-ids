import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { IDS_API_URL, IdsHistoryService, TrafficHistoryData } from './ids-history';

describe('IdsHistoryService', () => {
  it('should request the history of the given range from the backend', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: IDS_API_URL, useValue: 'http://backend.test' },
      ],
    });
    const http = TestBed.inject(HttpTestingController);
    const expected = { bucket_ms: 60000, points: [] } as unknown as TrafficHistoryData;
    let received: TrafficHistoryData | undefined;

    TestBed.inject(IdsHistoryService).load(168).subscribe((history) => (received = history));

    const request = http.expectOne('http://backend.test/api/history?hours=168');
    expect(request.request.method).toBe('GET');
    request.flush(expected);
    expect(received).toEqual(expected);
    http.verify();
  });
});

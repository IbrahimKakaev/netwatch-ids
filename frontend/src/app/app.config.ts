import { registerLocaleData } from '@angular/common';
import { provideHttpClient } from '@angular/common/http';
import localeFr from '@angular/common/locales/fr';
import { ApplicationConfig, LOCALE_ID, provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideRouter } from '@angular/router';
import { routes } from './app.routes';
import {
  DemoIdsHistoryService,
  DemoIdsWebsocketService,
  IDS_DEMO,
  isDemoMode,
} from './services/demo';
import { IdsHistoryService } from './services/ids-history';
import { IdsWebsocketService } from './services/ids-websocket';

// Nombres et heures au format français.
registerLocaleData(localeFr);

// En mode démo, le backend est remplacé par des sources de données simulées.
const demoProviders = isDemoMode(location)
  ? [
      { provide: IDS_DEMO, useValue: true },
      { provide: IdsWebsocketService, useClass: DemoIdsWebsocketService },
      { provide: IdsHistoryService, useClass: DemoIdsHistoryService },
    ]
  : [];

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideRouter(routes),
    provideHttpClient(),
    { provide: LOCALE_ID, useValue: 'fr' },
    ...demoProviders
  ]
};

import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AlertsPannel } from './alerts-pannel';

describe('AlertsPannel', () => {
  let component: AlertsPannel;
  let fixture: ComponentFixture<AlertsPannel>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AlertsPannel]
    })
    .compileComponents();

    fixture = TestBed.createComponent(AlertsPannel);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

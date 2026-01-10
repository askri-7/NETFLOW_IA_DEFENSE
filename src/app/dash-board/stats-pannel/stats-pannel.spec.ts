import { ComponentFixture, TestBed } from '@angular/core/testing';

import { StatsPannel } from './stats-pannel';

describe('StatsPannel', () => {
  let component: StatsPannel;
  let fixture: ComponentFixture<StatsPannel>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [StatsPannel]
    })
    .compileComponents();

    fixture = TestBed.createComponent(StatsPannel);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

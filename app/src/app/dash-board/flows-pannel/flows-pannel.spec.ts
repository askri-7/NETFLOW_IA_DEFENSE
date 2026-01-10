import { ComponentFixture, TestBed } from '@angular/core/testing';

import { FlowsPannel } from './flows-pannel';

describe('FlowsPannel', () => {
  let component: FlowsPannel;
  let fixture: ComponentFixture<FlowsPannel>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [FlowsPannel]
    })
    .compileComponents();

    fixture = TestBed.createComponent(FlowsPannel);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
